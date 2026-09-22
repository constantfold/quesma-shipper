package engine

import (
	"context"
	"fmt"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// Raw collection precedes enrichment; only a completed pass may forget vanished files.
func (o Options) collectSource(ctx context.Context, store *commitBuffer, src sources.Resolved, budget *int, rep *Report) (*SourceOutcome, error) {
	out := SourceOutcome{
		SourceID: src.ID,
		Family:   src.Family,
		Root:     src.Root,
		// A source that declares an emit key writes its own file rather than finding one.
		Emitted: src.Emit != "",
	}
	if !src.Enabled {
		out.Health = sources.AgentAbsent
		out.Reason = "disabled by configuration"
		return &out, nil
	}

	disc, err := sources.Discover(sources.Request{
		Source:   src,
		All:      o.Plan.Sources,
		Deny:     o.Plan.Deny,
		Ignore:   o.Plan.Ignore,
		StateDir: o.Plan.StateDir,
		Username: o.user,
		Now:      o.Now,
		Interval: o.Plan.Interval,
		Context:  ctx,
		Env:      o.Env,
		Capture:  !o.DryRun,
	})
	if err != nil {
		out.Health = sources.MatchPresentUnreadable
		out.Reason = err.Error()
		return &out, nil
	}
	out.Health = disc.Health
	out.Sniff = disc.Sniff
	out.AgentVersion = disc.AgentVersion
	out.Reason = disc.Reason

	// A spec change means this source is read differently, so its old state describes nothing.
	// Preview persists nothing and masks the stale entries instead, staying equal to a real sync.
	if o.DryRun {
		store.PreviewSpec(src.ID, src.SpecFingerprint)
	} else if _, err := store.EnsureSpec(src.ID, src.SpecFingerprint); err != nil {
		return nil, err
	}

	// One audit line per run rather than per path: a thousand denied paths under one unreadable
	// parent are one fact, not a thousand.
	out.Unreadable = disc.Unreadable
	out.UnreadableExample = disc.UnreadableExample
	out.UnreadableReason = disc.UnreadableReason
	if out.Unreadable > 0 {
		o.auditSource(src.ID, auditlog.Entry{
			Decision: auditlog.DecisionSkipped,
			File:     disc.UnreadableExample,
			Reason:   "not readable during discovery: " + disc.UnreadableReason,
		})
	}

	// Files the size cap kept out, audited one line each: "will never read it" is a decision.
	out.Oversize = len(disc.Oversize)
	for _, big := range disc.Oversize {
		if big.Size > out.OversizeLargest {
			out.OversizeLargest, out.OversizeExample, out.OversizeLimit = big.Size, big.RelPath, big.Limit
		}
		o.auditSource(src.ID, auditlog.Entry{
			Decision: auditlog.DecisionSkipped,
			File:     big.RelPath,
			BytesIn:  big.Size,
			Reason: fmt.Sprintf("over the size cap: %d bytes, limit %d — not read",
				big.Size, big.Limit),
		})
	}

	enrichers := o.enrichersFor(src)

	// Staged raw units live in memory for this source's pass only: there is no spool.
	pass := &sourcePass{
		o:       o,
		store:   store,
		src:     src,
		disc:    disc,
		rep:     rep,
		out:     &out,
		budget:  budget,
		staging: len(enrichers) > 0,
	}
	if err := pass.run(ctx); err != nil {
		// A refusal and an unavailable control plane both carry a source outcome worth
		// reporting; a cancelled context, the only other way this returns, does not.
		if stopsRun(err) {
			return &out, err
		}
		return nil, err
	}
	staged := pass.stagedUnits()

	// Enrichment runs only after every raw unit has shipped: an enricher cannot abort, park or
	// delay a raw file. A unit-free one runs every flush, gated only by shipDerived's output hash.
	for _, enricher := range enrichers {
		if len(staged) == 0 && enricher.NeedsUnits() {
			continue
		}
		if err := o.enrichSource(ctx, store, src, enricher, staged, &out, rep); err != nil {
			return &out, err
		}
	}

	// Forget files this source no longer has. Only a source that COLLECTED and returned
	// candidates proves absence, so a run the budget truncated forgets nothing.
	if !o.DryRun && out.Health == sources.Collected && len(disc.Candidates) > 0 && out.Remaining == 0 {
		live := make(map[string]bool, len(disc.Candidates))
		for _, c := range disc.Candidates {
			live[c.Path] = true
		}
		// Derived entries never appear among candidates, so they are kept by adding them here.
		for _, f := range out.Files {
			live[f.NativePath] = true
		}
		if n, derr := store.DropVanished(src.ID, live); derr != nil {
			return nil, derr
		} else if n > 0 {
			o.auditSource(src.ID, auditlog.Entry{
				Decision: auditlog.DecisionSkipped,
				Reason: fmt.Sprintf(
					"forgot %d fingerprint(s) for files this source no longer has", n),
			})
		}
	}

	// A source boundary bounds what a crash re-ships to the source in flight.
	if err := store.Flush(); err != nil {
		return nil, err
	}

	return &out, nil
}
