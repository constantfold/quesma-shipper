package engine

import (
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// fold is the only place a result touches the report, store, audit log and progress stream.
func (p *sourcePass) fold(r fileResult) {
	p.store.applyIntent(&r)
	// Only the first refusal or unavailable verdict is counted, or rep.Failed becomes a function
	// of GOMAXPROCS. The duplicates' intents still apply: one may have shipped before the refusal.
	if (r.outcome.Fatal && p.fatal) || (r.unavailable && p.uploadHalted) {
		return
	}

	if r.loadWarning != "" {
		p.out.Unreadable++
		p.out.UnreadableReason = r.loadWarning
		p.out.Reason = r.loadWarning
	}
	p.slots[r.idx] = r.outcome
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
	p.o.auditSource(r.outcome.SourceID, auditlog.Entry{
		Decision:         r.outcome.Decision,
		File:             r.outcome.NativePath,
		BytesIn:          r.outcome.BytesIn,
		BytesOut:         r.outcome.BytesOut,
		RedactionDensity: r.outcome.Density,
		RuleHits:         r.outcome.RuleHits,
		ObjectKey:        r.outcome.ObjectKey,
		Reason:           r.outcome.Reason,
	})
}

// stageUpload puts one sealed object into the authorization accumulator, which sends the group when
// the next object would take it past either bound. A true final means the result was decided here.
func (p *sourcePass) stageUpload(r fileResult) (res fileResult, final bool) {
	if p.fatal || p.uploadHalted {
		return p.abandon(r), true
	}
	p.staged.add(r)
	return fileResult{}, false
}

// drainStaged empties the accumulator once the run has stopped uploading.
func (p *sourcePass) drainStaged() []fileResult {
	if p.staged.len() == 0 || (!p.fatal && !p.uploadHalted) {
		return nil
	}
	items := p.staged.take()
	for i, it := range items {
		items[i] = p.abandon(it)
	}
	return items
}

// assemble moves the slots into the source outcome in candidate order; unfilled ones never decided.
func (p *sourcePass) assemble() {
	for _, outcome := range p.slots {
		if outcome.Decision != "" {
			p.out.Files = append(p.out.Files, outcome)
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

func (o Options) auditSource(sourceID string, entry auditlog.Entry) {
	entry.SourceID, entry.ConfigVersion = sourceID, o.Plan.ConfigVersion
	_ = o.Log.Append(entry)
}
