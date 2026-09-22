package engine

import (
	"cmp"
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
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
		out, err := o.collectSource(ctx, store, src, &budget, &rep)
		if out != nil {
			rep.Sources = append(rep.Sources, *out)
		}
		if err != nil {
			return rep, err
		}
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
