package engine

import "github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"

// commitBuffer batches fingerprint commits: every Commit re-encodes, validates and fsyncs every
// entry, so committing per file costs O(files x entries). An unflushed commit re-ships that file
// onto the same key, which bounds a crash to the flush limit rather than to one file.
type commitBuffer struct {
	store   *Store
	pending map[Key]Fingerprint
	limit   int

	// staleSpecs masks sources whose stored spec differs, on preview only, which persists nothing.
	staleSpecs map[string]bool
}

func newCommitBuffer(store *Store, limit int) *commitBuffer {
	if limit <= 0 {
		limit = 200
	}
	return &commitBuffer{store: store, pending: map[Key]Fingerprint{}, limit: limit, staleSpecs: map[string]bool{}}
}

// Get reads through the buffer: an unflushed commit is still the truth about what shipped.
func (b *commitBuffer) Get(k Key) (Fingerprint, bool) {
	if b.staleSpecs[k.SourceID] {
		return Fingerprint{}, false
	}
	if fp, ok := b.pending[k]; ok {
		return fp, true
	}
	return b.store.Get(k)
}

// Flush makes everything buffered durable in one document replacement.
func (b *commitBuffer) Flush() error {
	if len(b.pending) == 0 {
		return nil
	}
	if err := b.store.CommitAll(b.pending); err != nil {
		return err
	}
	clear(b.pending)
	return nil
}

func (b *commitBuffer) EnsureSpec(sourceID, specFingerprint string) (int, error) {
	if err := b.Flush(); err != nil {
		return 0, err
	}
	return b.store.EnsureSpec(sourceID, specFingerprint)
}

// PreviewSpec is EnsureSpec for preview: it masks a source whose stored spec differs rather than
// dropping it, so preview reports the same would-ship as a sync.
func (b *commitBuffer) PreviewSpec(sourceID, specFingerprint string) {
	if stored, known := b.store.specs[sourceID]; known && stored != specFingerprint {
		b.staleSpecs[sourceID] = true
	}
}

// DropVanished flushes first: a pending commit for a file the walk did not see would otherwise be
// written back right after being forgotten.
func (b *commitBuffer) DropVanished(sourceID string, live map[string]bool) (int, error) {
	if err := b.Flush(); err != nil {
		return 0, err
	}
	return b.store.DropVanished(sourceID, live)
}

// applyIntent makes a result durable. A failed commit rewrites the outcome before fold counts it,
// so "shipped but the record was lost" reads as failed.
func (b *commitBuffer) applyIntent(r *fileResult) {
	if r.commit == nil {
		return
	}
	b.pending[Key{SourceID: r.outcome.SourceID, NativePath: r.outcome.NativePath}] = *r.commit
	if len(b.pending) < b.limit {
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
