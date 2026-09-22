package engine

import (
	"cmp"
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
)

// Run performs one flush. Sources flush sequentially: the loop is poll-shaped, so a missed tick
// is a catch-up rather than a loss.
func Run(ctx context.Context, st *Store, o Options) (rep Report, err error) {
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
		o.Log = nil // a preview writes no audit lines
	}
	o.user = UsernameFromStateDir(o.StateDir)

	// Deferred LIFO: this runs after the flush below, since the run is not over while state is written.
	defer func() {
		rep.FinishedAt = o.Now()
		if o.scrub != nil {
			d, n := o.scrub.Slowest()
			rep.SlowestScrubNanos, rep.SlowestScrubBytes = int64(d), n
		}
		summarize(&rep)
	}()
	// A cancelled or failed run still makes durable what it shipped, without hiding why it stopped.
	defer func() {
		if ferr := store.Flush(); ferr != nil && err == nil {
			err = ferr
		}
	}()
	if len(o.Recipients) == 0 {
		// Encryption is mandatory in every version: an old client must be less capable, never less safe.
		return Report{}, errors.New("engine: no age recipients configured")
	}
	rep = Report{StartedAt: o.Now(), StoreCorrupt: st.Corrupt()}

	// Preview is exempt from pause: it ships nothing, and a paused owner may still look.
	if !o.DryRun {
		if p := platform.Read(o.StateDir); p.Paused {
			rep.Paused, rep.PauseReason = true, p.Reason
			return rep, nil
		}
	}

	// Compiled once per run and after the pause check, so a paused tick stays cheap.
	o.scrub, o.scrubErr = o.scrubber()

	budget := o.MaxFilesPerRun
	if o.Unbounded {
		budget = math.MaxInt // the drain's ctx deadline bounds the work instead
	}
	for _, src := range o.Sources {
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

	// Health reporting fails open; only redaction fails closed.
	if !o.DryRun && o.Heartbeat != nil {
		if err := o.Heartbeat(ctx, rep); err != nil {
			_ = o.Log.Append(auditlog.Entry{
				Decision: auditlog.DecisionFailed,
				Reason:   "heartbeat write failed: " + err.Error(),
			})
		}
	}
	return rep, nil
}

// summarize totals bytes from the outcomes, since derived outcomes bypass fold. Emitted and derived
// objects are excluded so an idle run totals zero.
func summarize(rep *Report) {
	var shippedIn []int64
	for _, s := range rep.Sources {
		if s.Emitted {
			continue
		}
		for _, f := range s.Files {
			if f.Derived {
				continue
			}
			rep.BytesRead += f.BytesIn
			rep.BytesSealed += f.BytesOut
			if f.Decision == formats.DecisionShipped {
				shippedIn = append(shippedIn, f.BytesIn)
			}
		}
	}
	rep.MedianFileBytes = 0
	if len(shippedIn) > 0 {
		slices.Sort(shippedIn)
		rep.MedianFileBytes = shippedIn[len(shippedIn)/2]
	}
}
