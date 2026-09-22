package engine

import (
	"context"
	"fmt"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// Raw collection precedes enrichment; only a completed pass may forget vanished files.
func (o Options) collectSource(ctx context.Context, store *commitBuffer, src sources.Resolved, budget *int, rep *Report) (*SourceOutcome, error) {
	out := SourceOutcome{SourceID: src.ID, Family: src.Family, Root: src.Root, Emitted: src.Emit != ""}
	if !src.Enabled {
		out.Health, out.Reason = formats.AgentAbsent, "disabled by configuration"
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
		out.Health, out.Reason = formats.MatchPresentUnreadable, err.Error()
		return &out, nil
	}
	out.Health, out.Sniff, out.AgentVersion, out.Reason = disc.Health, disc.Sniff, disc.AgentVersion, disc.Reason

	// A spec change means the old state describes nothing. Preview masks it instead of dropping it.
	if o.DryRun {
		store.PreviewSpec(src.ID, src.SpecFingerprint)
	} else if _, err := store.EnsureSpec(src.ID, src.SpecFingerprint); err != nil {
		return nil, err
	}

	// One audit line for unreadable paths: a thousand under one unreadable parent are one fact.
	out.Unreadable, out.UnreadableExample, out.UnreadableReason = disc.Unreadable, disc.UnreadableExample, disc.UnreadableReason
	if out.Unreadable > 0 {
		o.auditSource(src.ID, auditlog.Entry{
			Decision: auditlog.DecisionSkipped,
			File:     disc.UnreadableExample,
			Reason:   "not readable during discovery: " + disc.UnreadableReason,
		})
	}
	out.Oversize = len(disc.Oversize)
	for _, big := range disc.Oversize {
		if big.Size > out.OversizeLargest {
			out.OversizeLargest, out.OversizeExample, out.OversizeLimit = big.Size, big.RelPath, big.Limit
		}
		o.auditSource(src.ID, auditlog.Entry{
			Decision: auditlog.DecisionSkipped,
			File:     big.RelPath,
			BytesIn:  big.Size,
			Reason:   fmt.Sprintf("over the size cap: %d bytes, limit %d — not read", big.Size, big.Limit),
		})
	}

	enrichers := o.enrichersFor(src)
	pass := &sourcePass{o: o, store: store, src: src, disc: disc, rep: rep, out: &out, budget: budget, staging: len(enrichers) > 0}
	if err := pass.run(ctx); err != nil {
		// A refusal or unavailability carries an outcome worth reporting; a cancellation does not.
		if stopsRun(err) {
			return &out, err
		}
		return nil, err
	}
	staged := pass.stagedUnits()

	// Enrichment runs after every raw unit has shipped, so an enricher cannot hold up a raw file.
	for _, enricher := range enrichers {
		if len(staged) == 0 && enricher.NeedsUnits() {
			continue
		}
		if err := o.enrichSource(ctx, store, src, enricher, staged, &out, rep); err != nil {
			return &out, err
		}
	}

	// Only a source that collected every candidate proves absence; a truncated run forgets nothing.
	if !o.DryRun && out.Health == formats.Collected && len(disc.Candidates) > 0 && out.Remaining == 0 {
		live := make(map[string]bool, len(disc.Candidates))
		for _, c := range disc.Candidates {
			live[c.Path] = true
		}
		// Derived entries never appear among candidates.
		for _, f := range out.Files {
			live[f.NativePath] = true
		}
		n, err := store.DropVanished(src.ID, live)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			o.auditSource(src.ID, auditlog.Entry{
				Decision: auditlog.DecisionSkipped,
				Reason:   fmt.Sprintf("forgot %d fingerprint(s) for files this source no longer has", n),
			})
		}
	}

	// A source boundary bounds what a crash re-ships to the source in flight.
	if err := store.Flush(); err != nil {
		return nil, err
	}
	return &out, nil
}
