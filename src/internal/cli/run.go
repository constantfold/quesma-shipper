package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/crashjournal"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

// recoverFlush turns a panicking flush into an announced, audited error so the daemon survives it.
func recoverFlush(errOut io.Writer, log *auditlog.Log, flush func() (formats.Report, error)) (
	rep formats.Report, err error, panicked bool,
) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		panicked = true
		stack := string(debug.Stack())
		fmt.Fprintf(errOut, "PANIC in flush: %v\n%s\n", r, stack)
		fmt.Fprintf(errOut, "the tick was abandoned; the next one starts clean. "+
			"whatever caused this is still on disk and will be met again.\n")
		_ = log.Append(auditlog.Entry{
			Decision: auditlog.DecisionFailed,
			Reason:   fmt.Sprintf("panic in flush: %v", r),
			File:     firstStackFrame(stack),
		})
		err = fmt.Errorf("panic in flush: %v", r)
	}()
	rep, err = flush()
	return rep, err, false
}

func firstStackFrame(stack string) string {
	for _, line := range strings.Split(stack, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "quesma-shipper/internal/") && strings.Contains(line, ".go:") {
			return line
		}
	}
	return ""
}

const (
	recycleAfter           = 3 * time.Hour
	enrollmentPollInterval = 5 * time.Second
	// telemetryDeadline is short on purpose: a report about collection must never delay it.
	telemetryDeadline = 5 * time.Second
)

func recycleDue(started, now time.Time, serviceLoaded func() bool) bool {
	return now.Sub(started) >= recycleAfter && serviceLoaded()
}

// reportOutcome submits telemetry under its own bound, so it cannot spend the caller's budget.
func reportOutcome(ctx context.Context, env *app.Runtime) {
	ctx, cancel := context.WithTimeout(ctx, telemetryDeadline)
	defer cancel()
	env.SubmitTelemetry(ctx)
}

func flushBeforeExit(cmd *cobra.Command, env *app.Runtime) error {
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "\nsignal received, shipping one final slice before exit")
	ctx, cancel := context.WithTimeout(context.Background(), env.Effective().DrainDeadline)
	defer cancel()
	before := platform.ReadMemStats()
	rep, err := env.Flush(ctx, false)
	// Judged and reported like a tick: a final slice that failed every upload must outlive the process.
	tickErr := env.JudgeFinalSlice(err, rep, platform.Delta{Before: before, After: platform.ReadMemStats()})
	reportOutcome(ctx, env)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "final slice failed: %v\n", err)
		return nil
	}
	printRunSummary(out, rep, false)
	if tickErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "final slice sent nothing: %v\n", tickErr)
	}
	if rep.Remaining > 0 {
		fmt.Fprintf(out, "%d files remain; the next start resumes the backlog\n", rep.Remaining)
	}
	return nil
}

type runFlags struct{ once, drain, quiet bool }

func runCmd(build app.Build) *cobra.Command {
	var f runFlags
	cmd := verb("run", "Run the scheduler loop in the foreground", func(cmd *cobra.Command) error {
		if !f.once && (f.drain || f.quiet) {
			return fmt.Errorf("--drain and --quiet require --once")
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		// A config that does not resolve also reads as "not logged in" and cannot repair itself
		// between polls, so it skips the wait and lets app.New report the real reason.
		eff, paths, resolveErr := app.ResolveEffective()
		waiting := false
		for resolveErr == nil {
			if _, err := controlplane.LoadEnrollment(paths.StateDir); err == nil {
				break
			}
			if !waiting {
				fmt.Fprintln(cmd.ErrOrStderr(), "waiting for enrollment; run `quesma-shipper login` to continue")
				waiting = true
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(enrollmentPollInterval):
			}
			// Re-resolved each poll: login can land in a state_dir edited during the wait.
			eff, paths, resolveErr = app.ResolveEffective()
		}
		if !f.once {
			maybeSelfUpdate(ctx, build, resolveErr != nil || eff.AutoupdateEnabled, cmd.ErrOrStderr())
		}

		// After the self-update, whose re-exec would read as a death. Exit is not deferred: a panic
		// must skip it, since that missing entry is the crash record.
		stateDir, dirErr := paths.StateDir, error(nil)
		if resolveErr != nil {
			stateDir, dirErr = app.StateDirWithoutConfig()
		}
		fl, runID, lastCrash := startCrashJournal(cmd.ErrOrStderr(), stateDir, dirErr)
		err := runLoop(cmd, ctx, build, f, fl, runID, lastCrash)
		fl.Exit()
		return err
	})
	cmd.Long = "The development and debug mode: logs to stderr, Ctrl-C to stop, zero installation.\n" +
		"A tick is change DETECTION - size and mtime pre-filter, then a content hash - so\n" +
		"only changed sources go on to redact, seal and upload. Missed ticks are harmless:\n" +
		"the backlog is fingerprint-driven and oldest-first, so a late tick is a catch-up.\n" +
		"A tick cut short by max_files_per_run re-ticks after a short pause instead of\n" +
		"waiting the full interval, so a backlog converges at upload speed."
	cmd.Flags().BoolVar(&f.once, "once", false, "collect and send once, then exit")
	cmd.Flags().BoolVar(&f.drain, "drain", false, "send everything pending and block until done or drain_deadline")
	cmd.Flags().BoolVarP(&f.quiet, "quiet", "q", false, "no progress or summary; warnings, errors and the run log stay")
	return cmd
}

func runLoop(cmd *cobra.Command, ctx context.Context, build app.Build, f runFlags,
	fl *crashjournal.Log, runID string, lastCrash *formats.LastCrash) error {
	fl.Phase("init")

	env, err := app.New(build)
	if err != nil {
		// No runtime, so JudgeTick cannot record this; without it a broken config only reaches stderr.
		app.RecordStartupFailure("run", runID, err)
		return err
	}
	env.SetRunInfo(runID, lastCrash)
	env.OnCrashShipped = fl.Reported

	out, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	errOut := stderr
	var stream *progressStream
	if f.once {
		stream = newProgressStream(errOut, f.quiet)
		env.OnProgress = stream.emit
		env.OnLocked = func() { stream.openLog(env.StateDir()) }
		defer stream.closeLog()
		errOut = stream.Stderr()
	} else {
		packaging.RotateLogs(filepath.Join(env.StateDir(), "logs"))
	}
	reportRemote(errOut, env)

	// Resolved for --once too: the interval doubles as the stall watchdog's threshold.
	tick, tickWarn := config.TickInterval(env.Effective().Schedule)
	printWarning(errOut, tickWarn)
	if !f.once {
		limit, fromEnv := platform.SetSoftLimit(platform.DefaultSoftLimit)
		source := "default"
		if fromEnv {
			source = "GOMEMLIMIT"
		}
		fmt.Fprintf(out, "memory soft limit %d MB (%s)\n", limit>>20, source)
		fmt.Fprintf(out, "collecting to %s every %s; Ctrl-C to stop\n", env.Destination(), tick)
	}
	started := time.Now()

	for n := 1; ; n++ {
		fl.Phase(fmt.Sprintf("tick %d", n))
		// Roots are picked in app.New; an agent installed or first run later would otherwise stay
		// absent until a restart, and announcing it keeps that from passing silently.
		appeared := env.RefreshAbsentRoots()
		if !f.quiet {
			for _, id := range appeared {
				fmt.Fprintf(out, "source %s: root resolved, collecting from this tick\n", id)
			}
		}
		before := platform.ReadMemStats()
		var rep formats.Report
		var err error
		panicked, complete := false, true
		if f.drain {
			rep, complete, err = env.Drain(ctx)
		} else {
			// Not armed for a drain, whose bound is drain_deadline. Warns on the raw stderr: the
			// progress bar's writer is not safe for a second goroutine.
			wctx, stopWatch := context.WithCancel(context.Background())
			watchdogDone := make(chan struct{})
			go func() {
				env.WatchStalledTick(wctx, n, tick, stderr)
				close(watchdogDone)
			}()
			rep, err, panicked = recoverFlush(errOut, env.AuditLog(), func() (formats.Report, error) {
				return env.Flush(ctx, false)
			})
			// Joined, not just signalled: the judge is about to write the report the watchdog reads.
			stopWatch()
			<-watchdogDone
		}
		mem := platform.Delta{Before: before, After: platform.ReadMemStats()}
		if stream != nil {
			stream.Finish()
		}
		if ctx.Err() != nil {
			if f.once {
				return err
			}
			return flushBeforeExit(cmd, env)
		}
		// Judged before anything else reports: the record has to outlive the run.
		tickErr := env.JudgeTick(err, rep, panicked, mem)
		if err == nil && !f.quiet {
			printRunSummary(out, rep, f.once && !f.drain)
			if !f.once {
				fmt.Fprintf(out, "  memory\t%s\n", mem)
			}
		}
		// After the summary, so a slow collector cannot hold back the line the operator reads.
		reportOutcome(ctx, env)

		// The flush keeps its own error; the verdict only adds the run that completed and sent nothing.
		outcome := cmp.Or(err, tickErr)
		if f.once {
			switch {
			case outcome != nil:
				return outcome
			case f.drain && !complete:
				return fmt.Errorf("drain hit its %s deadline with work left: raise drain_deadline or accept the loss",
					env.Effective().DrainDeadline)
			case f.drain && !f.quiet:
				fmt.Fprintln(out, "drain complete: nothing pending")
			}
			return nil
		}
		if outcome != nil {
			fmt.Fprintf(errOut, "flush failed: %v\n", outcome)
		}
		if recycleDue(started, time.Now(), func() bool {
			return packaging.ServiceState(env.StateDir()).Loaded
		}) {
			fmt.Fprintf(out, "recycling after %s of uptime; replacing the process in place\n",
				time.Since(started).Round(time.Second))
			clearSelfUpdateHop()
			if err := packaging.ReExec(); err != nil {
				fmt.Fprintf(stderr, "recycle: re-exec failed (%v); exiting for the supervisor\n", err)
				app.RecordUpdateFailure(fmt.Sprintf("recycle re-exec failed, falling back to the supervisor: %v", err))
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return flushBeforeExit(cmd, env)
		case <-time.After(app.NextDelay(rep, err, tick)):
		}
	}
}
