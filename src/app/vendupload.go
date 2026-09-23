package app

// The write path: authorization client, upload-target allowlist and presigned uploader behind the
// engine's upload port. Wire types, tickets and URLs stop here; app alone imports controlplane and upload.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/upload"
)

// vendPort is the engine's UploadPort, one per process: a second would report two writers from one machine.
type vendPort struct {
	client   *controlplane.Client
	uploader *upload.Uploader
	targets  upload.UploadTargetList
	writerID string

	// now is the signing and ticket-expiry clock, a field so a test can fix it.
	now func() time.Time
}

// newControlPlaneClient builds the client from the enrollment alone, apart from the port, which also
// needs usable upload targets: telemetry needs only the client.
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
	deviceKey, err := enrollment.PrivateKey()
	if err != nil {
		return nil, err
	}
	return controlplane.New(controlplane.Options{
		Endpoint:     enrollment.Endpoint,
		InstallID:    enrollment.InstallID,
		Organization: enrollment.Organization,
		DeviceKey:    deviceKey,
	})
}

// newUploadPort needs no allowlist: without upload_targets tickets decide, https only and exact key.
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

// AuthorizeAndUpload authorizes the batch whole or not at all, then each object's PUT succeeds or fails alone.
func (p *vendPort) AuthorizeAndUpload(ctx context.Context, batch []engine.PreparedObject) []error {
	out := make([]error, len(batch))
	req, err := p.request(batch)
	if err != nil {
		return sameOutcome(out, err)
	}
	resp, err := p.client.AuthorizeUploads(ctx, req)
	if err != nil {
		return sameOutcome(out, classifyAuthorize(err))
	}

	tickets := make(map[string]controlplane.Ticket, len(resp.Tickets))
	for _, t := range resp.Tickets {
		if _, dup := tickets[t.ObjectID]; dup {
			return sameOutcome(out, fmt.Errorf(
				"upload: the control plane issued two tickets naming object %q", t.ObjectID))
		}
		tickets[t.ObjectID] = t
	}

	// Bounds the PUTs one group has in flight.
	slots := make(chan struct{}, 4*runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for i, obj := range batch {
		issued, ok := tickets[obj.ObjectID]
		if !ok {
			out[i] = fmt.Errorf(
				"upload: the control plane issued no ticket for object %q", obj.ObjectID)
			continue
		}
		// The archive holds these bytes already; the sentinel commits the fingerprint and marks the audit line.
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

// send validates the ticket against the object this machine prepared (origin, exact key, closed
// header set) before any byte leaves.
func (p *vendPort) send(ctx context.Context, obj engine.PreparedObject, issued controlplane.Ticket) error {
	if issued.AlreadyPresent {
		return nil
	}
	prepared := upload.PreparedUpload{
		ObjectID:   obj.ObjectID,
		Key:        obj.Key,
		Body:       obj.Body,
		SourceHash: obj.SourceHash,
		Metadata:   obj.Metadata,
	}
	ticket := toUploadTicket(issued)
	if err := upload.ValidateTicket(p.targets, prepared, ticket); err != nil {
		return err
	}
	// Nothing the store says crosses back: the local fingerprint document alone tracks progress.
	if err := p.uploader.Upload(ctx, ticket, obj.Body); err != nil {
		return p.classifyPut(err, ticket)
	}
	return nil
}

// request turns prepared objects into one signed authorization batch.
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

// uploadMetadata fails the batch on an unknown name: dropping it would ship plaintext metadata
// that disagrees with the manifest.
func uploadMetadata(md map[string]string) (controlplane.UploadMetadata, []string, error) {
	var out controlplane.UploadMetadata
	var dropped []string
	for name, value := range md {
		switch name {
		case "manifest-version":
			out.ManifestVersion = value
		case "source-id":
			out.SourceID = value
		case "shipped-hash":
			out.ShippedHash = value
		case "artifact-class":
			out.ArtifactClass = value
		case "agent-version":
			// Copied verbatim from the agent's file, so a bad value is dropped rather than fail every batch.
			if !printableASCII(value, 128) {
				dropped = append(dropped, fmt.Sprintf(
					"agent-version %q is not printable ASCII within 128 bytes; "+
						"shipping without it (the sealed manifest keeps it)", value))
				break
			}
			out.AgentVersion = value
		case "shape-sniff":
			out.ShapeSniff = value
		case "derived":
			out.Derived = value
		case "enrich-status":
			out.EnrichStatus = value
		case "kind":
			out.Kind = value
		case "source-hash", "ticket-id":
			return controlplane.UploadMetadata{}, nil, fmt.Errorf(
				"metadata %q is derived by the server and may not be requested", name)
		default:
			return controlplane.UploadMetadata{}, nil, fmt.Errorf(
				"metadata %q is outside the closed request set", name)
		}
	}
	return out, dropped, nil
}

// printableASCII is the control plane's plaintext-metadata grammar; empty passes, as absent is not sent.
func printableASCII(v string, max int) bool {
	return len(v) <= max && !strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e })
}

// classifyAuthorize maps to engine sentinels: refused credentials kill the install, an outage stops
// one run; the unavailable wrapping drops the chain so neither matches the other.
func classifyAuthorize(err error) error {
	switch {
	case errors.Is(err, formats.ErrCredentialsRefused):
		return err
	case errors.Is(err, controlplane.ErrAuthorizeUnavailable):
		return fmt.Errorf("%w: %v", engine.ErrUploadUnavailable, err)
	}
	return err
}

// classifyPut marks only a store refusal on an expired ticket as worth re-authorizing within the run.
func (p *vendPort) classifyPut(err error, ticket upload.Ticket) error {
	var status *upload.StatusError
	if !errors.As(err, &status) {
		return err
	}
	switch status.Status {
	case http.StatusForbidden, http.StatusBadRequest:
		if !ticket.ExpiresAt.IsZero() && p.now().After(ticket.ExpiresAt) {
			return fmt.Errorf("%w: %v", engine.ErrTicketExpired, err)
		}
	}
	return err
}

// sameOutcome gives the whole group one verdict when a failure has no per-object information.
func sameOutcome(out []error, err error) []error {
	for i := range out {
		out[i] = err
	}
	return out
}

// DescribeDestination names where objects go before a runtime exists, never a ticket path or
// query: those authorize the write.
func DescribeDestination(eff *config.Effective) string {
	if len(eff.UploadTargets) == 0 {
		// Worded to hold on local-dev too, where nothing uploads.
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

// uploadTargets refuses the whole allowlist on one bad entry, or the file would disagree with live origins.
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

// toUploadTicket clones headers; ValidateTicket refuses names outside the provider set.
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
