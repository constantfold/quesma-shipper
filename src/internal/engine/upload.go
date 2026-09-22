package engine

// The write path: sealed objects are authorized in bounded groups and PUT with short-lived
// tickets. The port is declared here, never imported, so the loop cannot know a control plane
// exists. The local fingerprint document alone says what shipped.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
)

// One authorization group's bounds: the protocol's declared limits and a memory bound at once.
const (
	maxBatchObjects = 32
	maxBatchBytes   = 64 << 20
)

// batcher accumulates sealed objects and sends a group once one more would breach either bound.
type batcher struct {
	maxObjects int
	send       func([]fileResult)

	items []fileResult
	bytes int64
}

func (b *batcher) add(it fileResult) {
	size := int64(len(it.pending.obj))
	// Sent before the append: a group past the declared ciphertext limit is refused whole.
	if len(b.items) > 0 && b.bytes+size > maxBatchBytes {
		b.flush()
	}
	b.items = append(b.items, it)
	b.bytes += size
	if len(b.items) >= b.maxObjects || b.bytes >= maxBatchBytes {
		b.flush()
	}
}

func (b *batcher) flush() {
	if items := b.take(); len(items) > 0 {
		b.send(items)
	}
}

// take hands off the batch; later appends cannot reuse its backing array.
func (b *batcher) take() []fileResult {
	items := b.items
	b.items, b.bytes = nil, 0
	return items
}

// PreparedObject is one sealed object offered for authorization. Body is the exact ciphertext PUT,
// so its length is the size the ticket is signed for.
type PreparedObject struct {
	// ObjectID pairs the object with its ticket, unique within the group and meaningless outside.
	ObjectID string
	Key      string
	Body     []byte

	// SourceHash is the manifest's raw pre-redaction digest, never a checksum of Body.
	SourceHash string

	// Metadata holds unprefixed plaintext names, source-hash excluded: hashes and versions only,
	// never the path, which stays inside the ciphertext.
	Metadata map[string]string
}

// UploadPort is the write path: one call authorizes a bounded batch and PUTs each member.
// Implementations validate every ticket against the prepared key before sending bytes, and return
// one result per input object in input order; nil means the PUT was confirmed, ErrAlreadyPresent
// means the control plane answered that the store already holds it.
type UploadPort interface {
	AuthorizeAndUpload(ctx context.Context, batch []PreparedObject) []error
}

var (
	// ErrUploadUnavailable is an authorization the control plane would not serve now. It must never
	// wrap formats.ErrCredentialsRefused: this install is waiting, not revoked.
	ErrUploadUnavailable = errors.New("engine: upload authorization is unavailable")

	// ErrTicketExpired is the only verdict worth a second authorization inside a single run.
	ErrTicketExpired = errors.New("engine: upload ticket had expired")

	// ErrAlreadyPresent commits like a confirmed PUT but marks the audit line, so an operator can
	// tell a commit resting on the plane's word from one this machine sent.
	ErrAlreadyPresent = errors.New("engine: the archive already held this object under the same source hash")
)

// sendBatch authorizes one group and turns each verdict into a file result, on a batch goroutine.
func (o Options) sendBatch(ctx context.Context, items []fileResult) []fileResult {
	outcomes := o.authorizeAndUpload(ctx, items)
	for i, it := range items {
		items[i] = applyUploadOutcome(it, outcomes[i])
	}
	return items
}

// preparedFrom lifts source-hash out of md into its own field; md is consumed, so edited in place.
func preparedFrom(idx int, key string, body []byte, md map[string]string) PreparedObject {
	if md == nil {
		md = map[string]string{}
	}
	hash := md["source-hash"]
	delete(md, "source-hash")
	return PreparedObject{ObjectID: strconv.Itoa(idx), Key: key, Body: body, SourceHash: hash, Metadata: md}
}

// authorizeAndUpload spends one group, with at most one reauthorization for expired tickets: a
// second expiry means the clock or the lease is wrong, and retrying only stalls everything else.
func (o Options) authorizeAndUpload(ctx context.Context, items []fileResult) []error {
	batch := make([]PreparedObject, len(items))
	for i, it := range items {
		batch[i] = preparedFrom(i, it.pending.objectKey, it.pending.obj, it.pending.md)
	}
	upload := func(objects []PreparedObject, description string) []error {
		outcomes := o.Upload.AuthorizeAndUpload(ctx, objects)
		if len(outcomes) != len(objects) {
			return slices.Repeat([]error{fmt.Errorf("engine: the upload port answered %d outcomes for %d %s",
				len(outcomes), len(objects), description)}, len(objects))
		}
		return outcomes
	}
	outcomes := upload(batch, "objects")

	var expired []int
	var again []PreparedObject
	for i, oc := range outcomes {
		if errors.Is(oc, ErrTicketExpired) {
			obj := batch[i]
			obj.ObjectID = strconv.Itoa(len(again))
			expired, again = append(expired, i), append(again, obj)
		}
	}
	if len(again) == 0 {
		return outcomes
	}
	// Whatever the second attempt says is final, expiry included.
	for i, oc := range upload(again, "reauthorized objects") {
		outcomes[expired[i]] = oc
	}
	return outcomes
}

// stopsRun reports the two verdicts that end a run's uploads rather than one file. A refusal kills
// the install, while unavailability stops only this run's uploads.
func stopsRun(err error) bool {
	return errors.Is(err, formats.ErrCredentialsRefused) || errors.Is(err, ErrUploadUnavailable)
}

const alreadyPresentReason = "no bytes sent: the control plane answered that the archive already holds this object"

// applyUploadOutcome is the verdict-to-decision map. A failed upload persists nothing and does not
// park, so the next run re-prepares the same key without delay.
func applyUploadOutcome(it fileResult, oc error) fileResult {
	r := it
	r.pending = nil
	out := &r.outcome

	// No stored-size cross-check here: upload.ValidateTicket refuses a length mismatch.
	present := errors.Is(oc, ErrAlreadyPresent)
	if oc != nil && !present {
		out.Decision, out.Reason = auditlog.DecisionFailed, oc.Error()
		// Derived refusals stop the enricher group without setting the raw pass's latch.
		out.Fatal = !out.Derived && errors.Is(oc, formats.ErrCredentialsRefused)
		r.unavailable = errors.Is(oc, ErrUploadUnavailable)
		return r
	}
	r.intent = intent{kind: intentShipped, key: it.pending.key, fp: it.pending.next}
	out.Decision = auditlog.DecisionShipped
	if present {
		out.Reason = alreadyPresentReason
	}
	return r
}
