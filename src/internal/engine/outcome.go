package engine

import (
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// fold is the only place a raw result touches the report, store, audit log and progress stream.
func (p *sourcePass) fold(r fileResult) {
	p.store.applyIntent(&r)
	// Only the first refusal or unavailable verdict counts, or rep.Failed becomes a function of
	// GOMAXPROCS. The duplicates' commits still apply: one may have shipped before the refusal.
	if (r.outcome.Fatal && p.fatal) || (r.unavailable && p.uploadHalted) {
		return
	}
	if r.loadWarning != "" {
		p.out.Unreadable++
		p.out.UnreadableReason, p.out.Reason = r.loadWarning, r.loadWarning
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

	// A stop gets no progress line and no per-file entry; the pass writes one at the end.
	if r.outcome.Fatal {
		p.fatal, p.fatalReason = true, r.outcome.Reason
		return
	}
	if r.unavailable {
		p.uploadHalted, p.haltReason = true, r.outcome.Reason
		return
	}

	if p.o.Progress != nil {
		p.o.Progress(p.src.ID, p.decided, len(p.disc.Candidates), r.outcome)
	}
	// Files the run never opened are elided into one aggregate entry; reading one is worth a line.
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

// stageUpload adds a sealed object to the accumulator; a true final means it was decided here.
func (p *sourcePass) stageUpload(r fileResult) (res fileResult, final bool) {
	if p.fatal || p.uploadHalted {
		return p.abandon(r), true
	}
	p.staged.add(r)
	return fileResult{}, false
}

// drainStaged empties the accumulator once the run has stopped uploading.
func (p *sourcePass) drainStaged() []fileResult {
	if !p.fatal && !p.uploadHalted {
		return nil
	}
	items := p.staged.take()
	for i, it := range items {
		items[i] = p.abandon(it)
	}
	return items
}

// abandon is a sealed object the pass will not send. Nothing commits, so the next run prepares it again.
func (p *sourcePass) abandon(r fileResult) fileResult {
	r.pending = nil
	r.outcome.Decision = auditlog.DecisionFailed
	r.outcome.Fatal = p.fatal
	// The non-fatal case is marked as a halt, so fold suppresses its duplicates too.
	r.unavailable = !p.fatal
	r.outcome.Reason = "not attempted: " + p.haltReason
	if p.fatal {
		r.outcome.Reason = "not attempted: this install's credentials were refused"
	}
	return r
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
