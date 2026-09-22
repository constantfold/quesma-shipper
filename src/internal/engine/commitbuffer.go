package engine

import (
	"cmp"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
)

// commitBuffer batches fingerprint writes, since each write re-encodes and fsyncs every entry. A
// commit lands in memory at once and on disk within limit commits, bounding what a crash re-ships.
type commitBuffer struct {
	*Store
	dirty, limit int

	// staleSpecs masks sources whose stored spec differs, on preview only, which persists nothing.
	staleSpecs map[string]bool
}

func newCommitBuffer(store *Store, limit int) *commitBuffer {
	return &commitBuffer{Store: store, limit: cmp.Or(limit, 200), staleSpecs: map[string]bool{}}
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

// PreviewSpec masks a source whose stored spec differs instead of dropping it, persisting nothing.
func (b *commitBuffer) PreviewSpec(sourceID, specFingerprint string) {
	if stored, known := b.specs[sourceID]; known && stored != specFingerprint {
		b.staleSpecs[sourceID] = true
	}
}

// applyIntent makes a result durable; a failed commit turns "shipped" into failed before fold counts it.
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
