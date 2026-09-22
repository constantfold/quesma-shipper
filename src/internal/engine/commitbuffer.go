package engine

import "github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"

// commitBuffer batches fingerprint writes: every write re-encodes, validates and fsyncs every
// entry, so writing per file costs O(files x entries). A commit lands in the store's memory at once
// and on disk within limit commits, which bounds what a crash re-ships onto the same keys.
type commitBuffer struct {
	*Store
	dirty, limit int

	// staleSpecs masks sources whose stored spec differs, on preview only, which persists nothing.
	staleSpecs map[string]bool
}

func newCommitBuffer(store *Store, limit int) *commitBuffer {
	if limit <= 0 {
		limit = 200
	}
	return &commitBuffer{Store: store, limit: limit, staleSpecs: map[string]bool{}}
}

func (b *commitBuffer) Get(k Key) (Fingerprint, bool) {
	if b.staleSpecs[k.SourceID] {
		return Fingerprint{}, false
	}
	return b.Store.Get(k)
}

// Flush makes every buffered commit durable in one document replacement.
func (b *commitBuffer) Flush() error {
	if b.dirty == 0 {
		return nil
	}
	if err := b.flush(); err != nil {
		return err
	}
	b.dirty = 0
	return nil
}

// PreviewSpec is EnsureSpec for preview: it masks a source whose stored spec differs rather than
// dropping it, so preview reports the same would-ship as a sync.
func (b *commitBuffer) PreviewSpec(sourceID, specFingerprint string) {
	if stored, known := b.specs[sourceID]; known && stored != specFingerprint {
		b.staleSpecs[sourceID] = true
	}
}

// applyIntent makes a result durable. A failed commit rewrites the outcome before fold counts it,
// so "shipped but the record was lost" reads as failed.
func (b *commitBuffer) applyIntent(r *fileResult) {
	if r.commit == nil {
		return
	}
	b.entries[Key{SourceID: r.outcome.SourceID, NativePath: r.outcome.NativePath}] = *r.commit
	if b.dirty++; b.dirty < b.limit {
		return
	}
	err := b.Flush()
	if err == nil {
		return
	}
	switch r.outcome.Decision {
	case auditlog.DecisionUnchanged:
		r.outcome.Decision, r.outcome.Reason = auditlog.DecisionFailed, err.Error()
	case auditlog.DecisionShipped:
		r.outcome.Decision = auditlog.DecisionFailed
		r.outcome.Reason = "upload succeeded but commit failed: " + err.Error()
		if r.outcome.Derived {
			r.outcome.Reason = "derived " + r.outcome.Reason
		}
	case auditlog.DecisionParked:
		r.outcome.Reason += " (and the backoff could not be recorded: " + err.Error() + ")"
	}
}
