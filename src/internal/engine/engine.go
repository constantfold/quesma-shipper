package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// Run performs one flush. Sources flush sequentially: the loop is poll-shaped, so a missed tick
// is a catch-up rather than a loss.
func Run(ctx context.Context, st *Store, o Options) (rep Report, err error) {
	// Commits batch for the run: an unflushed commit means the file ships again onto the same key.
	store := newCommitBuffer(st, o.CommitBatch)

	// Refusing here beats sealing every file and only then discovering there is nowhere to put them.
	if o.Upload == nil && !o.DryRun {
		return rep, errors.New("engine: no upload port; a run that ships needs one, and only " +
			"preview runs without it")
	}

	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.DryRun {
		// Decided once: a preview writes no audit lines, so every append below guards only on nil.
		o.Log = nil
	}
	o.user = UsernameFromStateDir(o.Plan.StateDir)

	// Runs first of the deferred summarization (LIFO): the run is not over while state is still being written.
	defer func() {
		rep.FinishedAt = o.Now()
		if o.scrub != nil {
			d, n := o.scrub.Slowest()
			rep.SlowestScrubNanos, rep.SlowestScrubBytes = int64(d), n
		}
		summarize(&rep)
	}()

	// Deferred so a cancelled or failed run still makes durable what it already shipped, without
	// letting a flush failure hide the reason the run stopped.
	defer func() {
		if ferr := store.Flush(); ferr != nil && err == nil {
			err = ferr
		}
	}()
	if len(o.Recipients) == 0 {
		// Encryption is mandatory in every version: an old client must be less capable, never less safe.
		return Report{}, errors.New("engine: no age recipients configured")
	}

	// After the report is built, not before: the assignment above replaces the whole struct.
	rep = Report{StartedAt: o.Now(), StoreCorrupt: st.Corrupt()}

	// The pause state is checked before anything is read. Preview is exempt: it ships and commits
	// nothing, and a paused owner may still see what would be collected.
	if !o.DryRun {
		if p := platform.Read(o.Plan.StateDir); p.Paused {
			rep.Paused = true
			rep.PauseReason = p.Reason
			return rep, nil
		}
	}

	// Redaction compiles once per run, not once per file or object, and only after the pause
	// gate: a paused tick must stay cheap. The compiled scrubber is immutable, so every pass's
	// goroutines share it; a compile failure still parks each candidate.
	o.scrub, o.scrubErr = o.scrubber()

	budget := o.Plan.MaxFilesPerRun
	if o.Unbounded {
		// A drain must flush EVERYTHING pending; its ctx deadline bounds the work instead.
		budget = math.MaxInt
	}

	for _, src := range o.Plan.Sources {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
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
			rep.Sources = append(rep.Sources, out)
			continue
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
			rep.Sources = append(rep.Sources, out)
			continue
		}
		out.Health = disc.Health
		out.Sniff = disc.Sniff
		out.AgentVersion = disc.AgentVersion
		out.Reason = disc.Reason

		// A spec change means this source is read differently, so its old state describes nothing.
		// Preview persists nothing and masks the stale entries instead, staying equal to a real sync.
		if o.DryRun {
			store.PreviewSpec(src.ID, src.SpecFingerprint)
		} else {
			if _, err := store.EnsureSpec(src.ID, src.SpecFingerprint); err != nil {
				return rep, err
			}
		}

		// One audit line per run rather than per path: a thousand denied paths under one unreadable
		// parent are one fact, not a thousand.
		out.Unreadable = disc.Unreadable
		out.UnreadableExample = disc.UnreadableExample
		out.UnreadableReason = disc.UnreadableReason
		if out.Unreadable > 0 {
			_ = o.Log.Append(auditlog.Entry{
				Decision:      auditlog.DecisionSkipped,
				SourceID:      src.ID,
				File:          disc.UnreadableExample,
				ConfigVersion: o.Plan.ConfigVersion,
				Reason:        "not readable during discovery: " + disc.UnreadableReason,
			})
		}

		// Files the size cap kept out, audited one line each: "will never read it" is a decision.
		out.Oversize = len(disc.Oversize)
		for _, big := range disc.Oversize {
			if big.Size > out.OversizeLargest {
				out.OversizeLargest, out.OversizeExample, out.OversizeLimit = big.Size, big.RelPath, big.Limit
			}
			_ = o.Log.Append(auditlog.Entry{
				Decision:      auditlog.DecisionSkipped,
				SourceID:      src.ID,
				File:          big.RelPath,
				BytesIn:       big.Size,
				ConfigVersion: o.Plan.ConfigVersion,
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
			rep:     &rep,
			out:     &out,
			budget:  &budget,
			staging: len(enrichers) > 0,
		}
		if err := pass.run(ctx); err != nil {
			// A refusal and an unavailable control plane both carry a source outcome worth
			// reporting; a cancelled context, the only other way this returns, does not.
			if stopsRun(err) {
				rep.Sources = append(rep.Sources, out)
			}
			return rep, err
		}
		staged := pass.stagedUnits()

		// Enrichment runs only after every raw unit has shipped: an enricher cannot abort, park or
		// delay a raw file. A unit-free one runs every flush, gated only by shipDerived's output hash.
		for _, enricher := range enrichers {
			if len(staged) == 0 && enricher.NeedsUnits() {
				continue
			}
			err := o.enrichSource(ctx, store, src, enricher, staged, &out, &rep)
			if err == nil {
				continue
			}
			rep.Sources = append(rep.Sources, out)
			return rep, err
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
				return rep, derr
			} else if n > 0 {
				_ = o.Log.Append(auditlog.Entry{
					Decision:      auditlog.DecisionSkipped,
					SourceID:      src.ID,
					ConfigVersion: o.Plan.ConfigVersion,
					Reason: fmt.Sprintf(
						"forgot %d fingerprint(s) for files this source no longer has", n),
				})
			}
		}

		// A source boundary bounds what a crash re-ships to the source in flight.
		if err := store.Flush(); err != nil {
			return rep, err
		}

		rep.Sources = append(rep.Sources, out)
	}

	slices.SortFunc(rep.Sources, func(a, b SourceOutcome) int { return cmp.Compare(a.SourceID, b.SourceID) })

	if !o.DryRun && o.Heartbeat != nil {
		// Health reporting fails open; only redaction fails closed.
		err := o.Heartbeat(ctx, rep)
		if err != nil {
			_ = o.Log.Append(auditlog.Entry{
				Decision: auditlog.DecisionFailed,
				Reason:   "heartbeat write failed: " + err.Error(),
			})
		}
	}
	return rep, nil
}
