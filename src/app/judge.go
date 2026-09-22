package app

// Tick classification, resource facts and failure heartbeats.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// JudgeTick classifies a flush; bookkeeping and failure heartbeats never change its verdict.
func (r *Runtime) JudgeTick(err error, rep formats.Report, panicked bool, mem platform.Delta) error {
	kind := formats.FailureTick
	if panicked {
		kind = formats.FailurePanic
	}
	return r.judge(err, rep, kind, mem)
}

// JudgeFinalSlice records drain failures separately: a disappearing host cannot retry.
func (r *Runtime) JudgeFinalSlice(err error, rep formats.Report, mem platform.Delta) error {
	return r.judge(err, rep, formats.FailureShutdown, mem)
}

func (r *Runtime) judge(err error, rep formats.Report, kind string, mem platform.Delta) error {
	if errors.Is(err, engine.ErrLocked) {
		return nil
	}
	if err == nil && rep.Shipped == 0 && rep.Failed > 0 {
		// Distinguish upload refusals from an unreachable control plane.
		err = fmt.Errorf("the run shipped nothing: all %d attempted uploads failed: %s",
			rep.Failed, firstFailureReason(rep))
	}

	r.persistRecord("tick outcome", os.Stderr, func(rec *formats.FailureRecord) {
		rec.Facts = r.runFacts(rep, mem)

		// A discarded store causes re-shipping, not a failed run.
		if rep.StoreCorrupt {
			rec.Append(newEvent(r.eff.StateDir, r.runID, formats.FailureStoreCorrupt,
				"the fingerprint store could not be loaded and was discarded; the next sync replaces it"))
		}

		if err == nil {
			// The next mid-flush heartbeat reads these facts from disk, including after a clean run.
			rec.ConsecutiveFailures = 0
		} else {
			ev := newEvent(r.eff.StateDir, r.runID, kind, err.Error())
			rec.Append(ev)
			if ev.Counted() {
				rec.ConsecutiveFailures++
			}
		}
	})

	if err == nil {
		// Kept for the stall heartbeat, which fires mid-tick when no fresh report exists yet.
		r.lastRep = rep
	}

	// Report local failures immediately; retrying failed uploads or a terminating drain would add another timeout.
	if err != nil && kind != formats.FailureShutdown && rep.Failed == 0 {
		r.shipFailureHeartbeat(context.Background(), rep, "failure record", os.Stderr)
	}
	return err
}

const failureHeartbeatTimeout = 30 * time.Second

// Failure heartbeats leave the local mirror describing the last real flush; parent cancellation suppresses warnings.
func (r *Runtime) shipFailureHeartbeat(parent context.Context, rep formats.Report, what string, errOut io.Writer) {
	if r.upload == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, failureHeartbeatTimeout)
	defer cancel()
	if err := r.writeHeartbeat(ctx, rep, false); err != nil && parent.Err() == nil {
		fmt.Fprintf(errOut, "warning: could not ship the %s: %v\n", what, err)
	}
}

// WatchStalledTick refreshes one standing event, doubling the reporting interval to bound fleet traffic.
func (r *Runtime) WatchStalledTick(ctx context.Context, n int, every time.Duration, errOut io.Writer) {
	if every <= 0 {
		return
	}
	started := time.Now()
	for wait := every; ; wait *= 2 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		elapsed := time.Since(started).Round(time.Second)
		fmt.Fprintf(errOut, "warning: tick %d still running after %s\n", n, elapsed)
		r.persistRecord("stalled tick", errOut, func(rec *formats.FailureRecord) {
			e := newEvent(r.eff.StateDir, r.runID, formats.FailureStalled,
				fmt.Sprintf("tick %d still running after %s", n, elapsed))
			// A later stall must replace the event left by a stall that recovered.
			if last := rec.Latest(); last != nil && last.Kind == formats.FailureStalled {
				*last = e
			} else {
				rec.Append(e)
			}
		})
		// Preserve source health when overwriting the remote heartbeat mid-tick.
		r.shipFailureHeartbeat(ctx, r.lastRep, "stall heartbeat", errOut)
	}
}

// runFacts records resource use and limits on every outcome, providing the next run's baseline.
func (r *Runtime) runFacts(rep formats.Report, mem platform.Delta) *formats.RunFacts {
	return &formats.RunFacts{
		GOMAXPROCS:       runtime.GOMAXPROCS(0),
		MaxFilesPerRun:   r.eff.MaxFilesPerRun,
		MaxInFlightBytes: platform.MaxInFlightBytes(),
		SoftLimitBytes:   platform.SoftLimit(),
		HeapInuseBytes:   mem.After.HeapInuse,
		SysBytes:         mem.After.Sys,
		GCCycles:         mem.After.NumGC - mem.Before.NumGC,

		SlowestScrubNanos: rep.SlowestScrubNanos,
		SlowestScrubBytes: rep.SlowestScrubBytes,
	}
}

// The audit log carries the remaining reasons.
func firstFailureReason(rep formats.Report) string {
	for _, s := range rep.Sources {
		for _, f := range s.Files {
			if f.Decision == formats.DecisionFailed && f.Reason != "" {
				return f.Reason
			}
		}
	}
	return "no reason recorded"
}
