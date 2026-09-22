package app

// The write path behind the engine's upload port: authorization client, upload-target allowlist and
// presigned uploader. Every wire type, ticket and URL stops here, because app is the only package
// allowed to import both controlplane and upload.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/upload"
)

// vendPort is the engine's UploadPort; one per process, since the writer id is one per process.
type vendPort struct {
	client   *controlplane.Client
	uploader *upload.Uploader
	targets  upload.UploadTargetList
	writerID string
	now      func() time.Time // signing and ticket-expiry clock, replaceable in tests
}

// newControlPlaneClient needs only the enrollment, so telemetry works even when upload targets do not.
func newControlPlaneClient(stateDir string) (*controlplane.Client, error) {
	enrollment, err := controlplane.LoadEnrollment(stateDir)
	if err != nil {
		return nil, fmt.Errorf("%w\n\nEvery upload is authorized by the control plane named in "+
			"the enrollment record. Fix it or log in again with `quesma-shipper login`", err)
	}
	if enrollment == nil || enrollment.Endpoint == "" {
		return nil, errors.New("uploading needs an enrolled control plane to authorize every object; " +
			"`quesma-shipper login` first (`quesma-shipper preview` works without it)")
	}
	return enrollment.Client()
}

// newUploadPort assembles the write path. The enrollment record is mandatory, the allowlist is not:
// with no upload_targets the tickets decide the destination, https only and exact key enforced.
func newUploadPort(client *controlplane.Client, eff *config.Effective) (*vendPort, error) {
	targets, err := uploadTargets(eff)
	if err != nil {
		return nil, err
	}
	return &vendPort{
		client:   client,
		uploader: upload.New(),
		targets:  targets,
		writerID: controlplane.NewWriterID(),
		now:      time.Now,
	}, nil
}

// AuthorizeAndUpload spends one bounded group: one authorization, then one PUT per ticket. The
// batch is authorized whole or not at all; past that point the objects succeed or fail alone.
func (p *vendPort) AuthorizeAndUpload(ctx context.Context, batch []engine.PreparedObject) []error {
	// Failures before the tickets carry no per-object information: one verdict for the group.
	req, err := p.request(batch)
	if err != nil {
		return slices.Repeat([]error{err}, len(batch))
	}
	resp, err := p.client.AuthorizeUploads(ctx, req)
	if err != nil {
		return slices.Repeat([]error{classifyAuthorize(err)}, len(batch))
	}

	tickets := make(map[string]controlplane.Ticket, len(resp.Tickets))
	for _, t := range resp.Tickets {
		if _, dup := tickets[t.ObjectID]; dup {
			return slices.Repeat([]error{fmt.Errorf(
				"upload: the control plane issued two tickets naming object %q", t.ObjectID)}, len(batch))
		}
		tickets[t.ObjectID] = t
	}

	out := make([]error, len(batch))
	// Bounds the PUTs one authorization group has in flight.
	slots := make(chan struct{}, 4*runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for i, obj := range batch {
		issued, ok := tickets[obj.ObjectID]
		if !ok {
			out[i] = fmt.Errorf(
				"upload: the control plane issued no ticket for object %q", obj.ObjectID)
			continue
		}
		// The archive already holds these bytes: the sentinel commits the fingerprint without a PUT.
		if issued.AlreadyPresent {
			out[i] = engine.ErrAlreadyPresent
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			out[i] = p.send(ctx, obj, issued)
		}()
	}
	wg.Wait()
	return out
}

// send validates the ticket against the object this machine prepared before any byte leaves.
func (p *vendPort) send(ctx context.Context, obj engine.PreparedObject, issued controlplane.Ticket) error {
	ticket := toUploadTicket(issued)
	if err := upload.ValidateTicket(p.targets, upload.PreparedUpload(obj), ticket); err != nil {
		return err
	}
	if err := p.uploader.Upload(ctx, ticket, obj.Body); err != nil {
		return p.classifyPut(err, ticket)
	}
	return nil
}

func (p *vendPort) request(batch []engine.PreparedObject) (controlplane.AuthorizeRequest, error) {
	objects := make([]controlplane.UploadObject, len(batch))
	for i, o := range batch {
		md, dropped, err := uploadMetadata(o.Metadata)
		if err != nil {
			return controlplane.AuthorizeRequest{}, fmt.Errorf("upload: object %q: %w", o.ObjectID, err)
		}
		for _, d := range dropped {
			fmt.Fprintf(os.Stderr, "warning: object %s: %s\n", o.Key, d)
		}
		objects[i] = controlplane.UploadObject{
			ObjectID:   o.ObjectID,
			Key:        o.Key,
			Size:       int64(len(o.Body)),
			SourceHash: o.SourceHash,
			Metadata:   md,
		}
	}
	return controlplane.AuthorizeRequest{
		WriterID: p.writerID,
		IssuedAt: p.now().UTC(),
		Objects:  objects,
	}, nil
}

// uploadMetadata maps manifest metadata onto the closed request set, name by name. An unknown name
// fails the whole batch: dropping it would ship plaintext metadata disagreeing with the manifest.
func uploadMetadata(md map[string]string) (controlplane.UploadMetadata, []string, error) {
	for name := range md {
		switch {
		case name == "source-hash" || name == "ticket-id":
			return controlplane.UploadMetadata{}, nil, fmt.Errorf(
				"metadata %q is derived by the server and may not be requested", name)
		case !slices.Contains(upload.MetadataNames, name):
			return controlplane.UploadMetadata{}, nil, fmt.Errorf(
				"metadata %q is outside the closed request set", name)
		}
	}
	out := controlplane.UploadMetadata{
		ManifestVersion: md["manifest-version"],
		SourceID:        md["source-id"],
		ShippedHash:     md["shipped-hash"],
		ArtifactClass:   md["artifact-class"],
		AgentVersion:    md["agent-version"],
		ShapeSniff:      md["shape-sniff"],
		Derived:         md["derived"],
		EnrichStatus:    md["enrich-status"],
		Kind:            md["kind"],
	}
	// A malformed agent version must not block the whole batch; the sealed manifest keeps it. The
	// control plane accepts up to 128 bytes of printable ASCII.
	v := out.AgentVersion
	if len(v) <= 128 && !strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return out, nil, nil
	}
	out.AgentVersion = ""
	return out, []string{fmt.Sprintf("agent-version %q is not printable ASCII within 128 bytes; "+
		"shipping without it (the sealed manifest keeps it)", v)}, nil
}

// classifyAuthorize keeps refused credentials (kills the install) apart from an outage (stops one
// run); the unavailable wrapping drops the chain so neither can find the other.
func classifyAuthorize(err error) error {
	if errors.Is(err, controlplane.ErrAuthorizeUnavailable) && !errors.Is(err, formats.ErrCredentialsRefused) {
		return fmt.Errorf("%w: %v", engine.ErrUploadUnavailable, err)
	}
	return err
}

// classifyPut names the one PUT failure worth a second authorization inside a run: a store refusal
// on a ticket whose own expiry has passed. Every other refusal waits for the next run.
func (p *vendPort) classifyPut(err error, ticket upload.Ticket) error {
	var status *upload.StatusError
	if !errors.As(err, &status) {
		return err
	}
	refused := status.Status == http.StatusForbidden || status.Status == http.StatusBadRequest
	if refused && !ticket.ExpiresAt.IsZero() && p.now().After(ticket.ExpiresAt) {
		return fmt.Errorf("%w: %v", engine.ErrTicketExpired, err)
	}
	return err
}

// DescribeDestination names where objects go without printing a ticket URL, which is a credential.
// The no-target wording also holds on a local-dev install, where nothing uploads.
func DescribeDestination(eff *config.Effective) string {
	if len(eff.UploadTargets) == 0 {
		return "presigned upload (no pinned origins; set upload_targets to pin)"
	}
	origins := make([]string, 0, len(eff.UploadTargets))
	for _, t := range eff.UploadTargets {
		origins = append(origins, t.Origin)
	}
	return "presigned upload -> " + strings.Join(origins, ", ")
}

func DestinationHosts(destination, endpoint string) string {
	if _, origins, ok := strings.Cut(destination, "-> "); ok {
		return origins
	}
	return strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
}

// uploadTargets builds the allowlist; one bad entry refuses the whole list, or the operator's file
// would disagree with the live origins.
func uploadTargets(eff *config.Effective) (upload.UploadTargetList, error) {
	list := make(upload.UploadTargetList, 0, len(eff.UploadTargets))
	for i, t := range eff.UploadTargets {
		target, err := upload.NewUploadTarget(upload.TargetSpec{
			Origin:            t.Origin,
			Addressing:        upload.Addressing(t.Addressing),
			PathPrefix:        t.PathPrefix,
			AllowLoopbackHTTP: t.AllowLoopbackHTTP,
		})
		if err != nil {
			return nil, fmt.Errorf("upload_targets entry %d: %w", i, err)
		}
		list = append(list, target)
	}
	return list, nil
}

// toUploadTicket copies one issued ticket into the uploader's shape.
func toUploadTicket(t controlplane.Ticket) upload.Ticket {
	return upload.Ticket{
		TicketID:            t.TicketID,
		ObjectID:            t.ObjectID,
		Method:              t.Method,
		URL:                 t.URL,
		ExpiresAt:           t.ExpiresAt,
		RequiredHeaders:     maps.Clone(t.RequiredHeaders),
		ContentLength:       t.ContentLength,
		ContentLengthSigned: t.ContentLengthSigned,
	}
}
