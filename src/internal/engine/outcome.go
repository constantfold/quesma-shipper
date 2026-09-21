package engine

import (
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// fold is the only place a result touches the report, store, audit log and progress stream.
func (p *sourcePass) fold(r fileResult) {
	// Only the first refusal or unavailable verdict is counted, or rep.Failed becomes a function
	// of GOMAXPROCS. The duplicates' intents still apply: one may have shipped before the refusal.
	if (r.outcome.Fatal && p.fatal) || (r.unavailable && p.uploadHalted) {
		p.applyIntent(&r)
		return
	}

	p.applyIntent(&r)
	if r.loadWarning != "" {
		p.out.Unreadable++
		p.out.UnreadableReason = r.loadWarning
		p.out.Reason = r.loadWarning
	}
	p.slots[r.idx], p.filled[r.idx] = r.outcome, true
	p.units[r.idx] = r.unit
	p.decided++

	switch r.outcome.Decision {
	case auditlog.DecisionShipped:
		p.rep.Shipped++
	case auditlog.DecisionUnchanged:
		p.rep.Unchanged++
		*p.budget++
	case auditlog.DecisionSkipped:
		p.rep.Skipped++
		*p.budget++
	case auditlog.DecisionParked:
		p.rep.Parked++
	case auditlog.DecisionFailed:
		p.rep.Failed++
	}

	if r.outcome.Fatal {
		// The refusal gets no progress line and no per-file entry; the pass writes one at the end.
		p.fatal = true
		p.fatalReason = r.outcome.Reason
		return
	}
	if r.unavailable {
		// Latched on the loop thread, so the admission gate and accumulator see it on the next turn.
		p.uploadHalted = true
		p.haltReason = r.outcome.Reason
		return
	}

	if p.o.Progress != nil {
		// done counts decisions, not positions: still monotonic, and still ends at total.
		p.o.Progress(p.src.ID, p.decided, len(p.disc.Candidates), r.outcome)
	}
	// Elided into one aggregate entry: a line per unchanged file grows the log at scan rate.
	// Only files the run never OPENED are elided; reading one is doing something worth a line.
	if r.outcome.Decision == auditlog.DecisionUnchanged && r.outcome.BytesIn == 0 {
		p.unchangedElided++
		return
	}
	_ = p.o.Log.Append(auditlog.Entry{
		Decision:         r.outcome.Decision,
		SourceID:         r.outcome.SourceID,
		File:             r.outcome.NativePath,
		BytesIn:          r.outcome.BytesIn,
		BytesOut:         r.outcome.BytesOut,
		RedactionDensity: r.outcome.Density,
		RuleHits:         r.outcome.RuleHits,
		ObjectKey:        r.outcome.ObjectKey,
		ConfigVersion:    p.o.Plan.ConfigVersion,
		Reason:           r.outcome.Reason,
	})
}

// applyIntent makes a result durable. A failed commit rewrites the outcome BEFORE fold counts it,
// so "shipped but the record was lost" reads as failed.
func (p *sourcePass) applyIntent(r *fileResult) {
	if r.intent.kind == intentNone {
		return
	}
	err := p.store.Commit(r.intent.key, r.intent.fp)
	if err == nil {
		return
	}
	switch r.intent.kind {
	case intentRefresh:
		r.outcome.Decision = auditlog.DecisionFailed
		r.outcome.Reason = err.Error()
	case intentShipped:
		r.outcome.Decision = auditlog.DecisionFailed
		r.outcome.Reason = "upload succeeded but commit failed: " + err.Error()
	case intentBackoff:
		r.outcome.Reason = r.intent.reason +
			" (and the backoff could not be recorded: " + err.Error() + ")"
	}
}

// stageUpload puts one sealed object into the authorization accumulator, which sends the group when
// the next object would take it past either bound. A true final means the result was decided here.
func (p *sourcePass) stageUpload(r fileResult) (res fileResult, final bool) {
	pending := r.pending
	r.pending = nil
	it := stagedUpload{res: r, pending: pending}

	if p.fatal || p.uploadHalted {
		return p.abandon(it), true
	}
	p.staged.add(it, int64(len(pending.obj)))
	return fileResult{}, false
}

// drainStaged empties the accumulator once the run has stopped uploading.
func (p *sourcePass) drainStaged() []fileResult {
	if p.staged.len() == 0 || (!p.fatal && !p.uploadHalted) {
		return nil
	}
	items := p.staged.take()
	out := make([]fileResult, len(items))
	for i, it := range items {
		out[i] = p.abandon(it)
	}
	return out
}

// assemble moves the slots into the source outcome in candidate order; unfilled ones never decided.
func (p *sourcePass) assemble() {
	for i, ok := range p.filled {
		if ok {
			p.out.Files = append(p.out.Files, p.slots[i])
		}
	}
}

// stagedUnits is the enricher's input, in candidate order like everything else.
func (p *sourcePass) stagedUnits() []transforms.RawUnit {
	var staged []transforms.RawUnit
	for _, u := range p.units {
		if u != nil {
			staged = append(staged, *u)
		}
	}
	return staged
}
