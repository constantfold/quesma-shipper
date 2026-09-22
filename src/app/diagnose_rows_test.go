package app

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

// TestDiscoveryRowsSeverity pins the severity of every health state, and that NO source state
// is SevFail: a broken source loses that source's data, never the exit code.
func TestDiscoveryRowsSeverity(t *testing.T) {
	src := config.ResolvedSource{Source: sources.Source{ID: "s"}}
	cases := []struct {
		name    string
		d       sources.Discovery
		wantSev Severity
		wantFix string // substring of the first row's fix; empty means no fix expected
	}{
		{"collected", sources.Discovery{Health: sources.Collected, Sniff: sources.SniffOK}, SevOK, ""},
		{"collected_bad_sniff",
			sources.Discovery{Health: sources.Collected, Sniff: sources.SniffUnexpectedShape},
			SevWarn, "quesma-shipper preview"},
		{"agent_absent", sources.Discovery{Health: sources.AgentAbsent, Reason: "no root"}, SevDim, ""},
		{"moved", sources.Discovery{Health: sources.RootPresentNoMatch, Reason: "root exists"}, SevWarn, "moved"},
		{"unreadable", sources.Discovery{Health: sources.MatchPresentUnreadable, Reason: "denied"},
			SevWarn, "permissions"},
	}
	for _, c := range cases {
		rows := discoveryRows(src, c.d)
		require.NotEmpty(t, rows)
		assert.Equal(t, c.wantSev, rows[0].Sev, c.name)
		assert.Contains(t, rows[0].Fix, c.wantFix, c.name)
		for _, row := range rows {
			assert.NotEqual(t, SevFail, row.Sev)
		}
	}
}

// Size-cap and unreadable counts each get their own warning with the exact remedy.
func TestDiscoveryRowsLossSubRows(t *testing.T) {
	src := config.ResolvedSource{Source: sources.Source{ID: "claude"}}
	rows := discoveryRows(src, sources.Discovery{
		Health: sources.Collected, Sniff: sources.SniffOK,
		Unreadable: 2, UnreadableReason: "permission denied", UnreadableExample: "/x/y",
		Oversize: []sources.Oversize{{RelPath: "big", Size: 200, Limit: 100}},
	})
	require.Len(t, rows, 3)
	assert.Equal(t, []Severity{SevOK, SevWarn, SevWarn}, []Severity{rows[0].Sev, rows[1].Sev, rows[2].Sev})
	assert.Contains(t, rows[1].Fix, "/x/y")
	assert.Contains(t, rows[2].Fix, "max_file_bytes")
}

func TestCheckUpdate(t *testing.T) {
	ctx := context.Background()
	noEnv := func(string) string { return "" }
	published := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	fixed := func(latest string, available bool, err error) func(context.Context, packaging.UpdateOptions) (string, time.Time, bool, error) {
		return func(context.Context, packaging.UpdateOptions) (string, time.Time, bool, error) {
			return latest, published, available, err
		}
	}
	boom := func(context.Context, packaging.UpdateOptions) (string, time.Time, bool, error) {
		t.Fatal("a dev build or a disabled check must not touch the network")
		return "", time.Time{}, false, nil
	}

	disabled := func(k string) string {
		if k == NoSelfUpdateEnv {
			return "1"
		}
		return ""
	}
	assert.Equal(t, "disabled", checkUpdate(ctx, Build{Release: true}, true, disabled, boom).State)
	assert.Equal(t, "disabled", checkUpdate(ctx, Build{Release: true}, false, noEnv, boom).State)
	// A dev build never checks: no TUF, no source repository, no network.
	assert.Equal(t, "skipped", checkUpdate(ctx, Build{Release: false}, true, noEnv, boom).State)
	assert.Equal(t, "failed", checkUpdate(ctx, Build{Release: true}, true, noEnv, fixed("", false, errors.New("dns"))).State)
	got := checkUpdate(ctx, Build{Release: true, Version: "1.0.0"}, true, noEnv, fixed("1.1.0", true, nil))
	assert.Truef(t, got.State == "available" && got.Fix == "quesma-shipper update", "available: %+v must name the command to run", got)
	assert.Containsf(t, got.Detail, "2026-08-18", "available: %q must date the release", got.Detail)
	assert.Equal(t, "current", checkUpdate(ctx, Build{Release: true}, true, noEnv, fixed("1.0.0", false, nil)).State)
}

// Everything status shares with doctor stays out of the exit code. Seeded so the rows that only
// appear on a broken install are in the set: an empty dir would leave the warning paths untested.
func TestAdvisoryRowsNeverFail(t *testing.T) {
	dir := t.TempDir()
	const mine, theirs = "c033b5b2-c3ac-4f39-911f-7ea632b7727c", "85a7e04c-32a4-4bf5-9c80-49c4f9d087bb"
	seedFailures(t, dir, 19, event(time.Now(), formats.FailureTick, "the run shipped nothing"))

	var rows []Row
	rows = append(rows, scheduleRows(dir, time.Now())...)
	doc, docErr := engine.Peek(dir)
	rows = append(rows, stateRowsFrom(doc, docErr, "")...)
	rows = append(rows, stateRowsFrom(engine.Document{InstallID: theirs}, nil, mine)...)
	rows = append(rows, stateRowsFrom(engine.Document{}, errors.New("unreadable"), mine)...)
	rows = append(rows, enrollmentRows(dir, nil, os.ErrNotExist, &config.Effective{}, controlplane.Remote{})...)
	rows = append(rows, enrollmentRows(dir, nil, errors.New("corrupt"), &config.Effective{}, controlplane.Remote{})...)
	var labels []string
	for _, row := range rows {
		assert.NotEqualf(t, SevFail, row.Sev, "advisory row %q is SevFail", row.Label)
		labels = append(labels, row.Label)
	}
	// The seeding is the point: a refactor that stops producing these must not quietly pass.
	for _, want := range []string{"recent runs", "local state"} {
		assert.Truef(t, slices.Contains(labels, want), "the %q row never appeared, so its severity went unchecked: %v", want, labels)
	}
}

// TestFamilyRows pins the agent-grouped view: one headline per agent, sub-rows for findings.
func TestFamilyRows(t *testing.T) {
	probe := func(id, family string, d sources.Discovery) sourceProbe {
		return sourceProbe{src: config.ResolvedSource{Source: sources.Source{ID: id, Family: family}}, d: d}
	}
	enable := func(pr sourceProbe) sourceProbe { pr.src.Enabled = true; return pr }

	t.Run("healthy multi-source agent is one line", func(t *testing.T) {
		rows, collecting, files := familyRows("Claude Code", []sourceProbe{
			enable(probe("claude-code-transcripts", "claude-code",
				sources.Discovery{Health: sources.Collected, Sniff: sources.SniffOK,
					Candidates: make([]sources.Candidate, 1200)})),
			enable(probe("claude-code-context", "claude-code",
				sources.Discovery{Health: sources.Collected, Sniff: sources.SniffOK,
					Candidates: make([]sources.Candidate, 34)})),
		}, familyUpload{}, time.Now(), true)
		require.Truef(t, collecting && files == 1234, "collecting=%v files=%d", collecting, files)
		require.Lenf(t, rows, 1, "healthy agent must be one row, got %d: %+v", len(rows), rows)
		if rows[0].Sev != SevOK || rows[0].Label != "Claude Code" {
			t.Errorf("headline: %+v", rows[0])
		}
		for _, want := range []string{"1,234 files", "transcripts", "context"} {
			assert.Containsf(t, rows[0].Detail, want, "detail %q missing %q", rows[0].Detail, want)
		}
	})

	t.Run("headline version tag comes from the sniffed store, not an exec", func(t *testing.T) {
		rows, _, _ := familyRows("Claude Code", []sourceProbe{
			enable(probe("claude-code-transcripts", "claude-code",
				sources.Discovery{Health: sources.Collected, Sniff: sources.SniffOK,
					AgentVersion: "2.1.245", Candidates: make([]sources.Candidate, 3)})),
		}, familyUpload{}, time.Now(), false)
		assert.Equalf(t, "2.1.245", rows[0].Tag, "headline tag %q, want the sniffed version 2.1.245", rows[0].Tag)
	})

	t.Run("a sibling source with no files is a note, not a finding", func(t *testing.T) {
		probes := []sourceProbe{
			enable(probe("codex-rollouts", "codex",
				sources.Discovery{Health: sources.Collected, Sniff: sources.SniffOK})),
			enable(probe("codex-rollouts-compressed", "codex",
				sources.Discovery{Health: sources.RootPresentNoMatch, Reason: "nothing matched"})),
		}
		rows, _, _ := familyRows("Codex", probes, familyUpload{}, time.Now(), false)
		require.Truef(t, len(rows) == 1 && rows[0].Sev == SevOK, "default view: headline ✓ and nothing else, got %+v", rows)
		rows, _, _ = familyRows("Codex", probes, familyUpload{}, time.Now(), true)
		require.Truef(t, len(rows) == 2 && rows[1].Sev == SevDim && rows[1].Sub && strings.Contains(rows[1].Detail, "no rollouts-compressed files yet"), "--all: a dim note under the headline, got %+v", rows)
	})

	t.Run("an agent whose only folder has nothing is a finding that names the folder", func(t *testing.T) {
		src := probe("codex-rollouts", "codex", sources.Discovery{Health: sources.RootPresentNoMatch})
		src.src.Root = "/home/x/.codex/sessions"
		rows, _, _ := familyRows("Codex", []sourceProbe{enable(src)}, familyUpload{}, time.Now(), false)
		require.Truef(t, len(rows) == 2 && rows[0].Sev == SevWarn && rows[1].Sub, "want a ! headline and one Sub finding, got %+v", rows)
		assert.Truef(t, strings.Contains(rows[1].Detail, "/home/x/.codex/sessions") && strings.Contains(rows[1].Detail, "Codex may have changed where it writes"), "the finding must name the folder and the likely cause: %q", rows[1].Detail)
		r := &Report{Sections: []Section{{Rows: rows}}}
		if iss, fails := r.Issues(); len(iss)-fails != 1 {
			t.Errorf("one agent with one finding must count as 1 issue, got %d", len(iss)-fails)
		}
	})

	t.Run("disabled source is dim, never a finding", func(t *testing.T) {
		rows, collecting, _ := familyRows("Cursor", []sourceProbe{
			probe("cursor-transcripts", "cursor", sources.Discovery{}),
		}, familyUpload{}, time.Now(), true)
		require.Truef(t, !collecting && rows[0].Sev == SevDim && strings.Contains(rows[0].Detail, "disabled by configuration"), "a deliberately disabled agent must headline dim: %+v", rows)
		r := &Report{Sections: []Section{{Rows: rows}}}
		if iss, fails := r.Issues(); fails != 0 || len(iss) != 0 {
			t.Errorf("disabled by configuration must not count: fails=%d issues=%d", fails, len(iss))
		}
	})

	t.Run("absent agent is one dim line", func(t *testing.T) {
		rows, collecting, _ := familyRows("Wire-capture proxy", []sourceProbe{
			enable(probe("wire-proxy-flows", "wire-proxy",
				sources.Discovery{Health: sources.AgentAbsent, Reason: "no root"})),
		}, familyUpload{}, time.Now(), true)
		require.Truef(t, !collecting && len(rows) == 1 && rows[0].Sev == SevDim, "absence must be one dim row: %+v", rows)
		assert.Containsf(t, rows[0].Detail, "not installed", "detail %q should say not installed", rows[0].Detail)
	})
}

// The per-agent upload answer, with failures escalating to a warning.
func TestFamilyUploadRow(t *testing.T) {
	probes := []sourceProbe{{
		src: config.ResolvedSource{Source: sources.Source{ID: "x", Family: "f"}, Enabled: true},
		d:   sources.Discovery{Health: sources.Collected, Sniff: sources.SniffOK, Candidates: make([]sources.Candidate, 5)},
	}}
	now := time.Now()

	rows, _, _ := familyRows("F", probes,
		familyUpload{recorded: true, at: now.Add(-9 * time.Minute), shipped: 12, pending: 3}, now, true)
	require.Truef(t, len(rows) == 2 && rows[1].Label == "  last upload" && rows[1].Sev == SevDim, "expected a dim last-upload sub-row: %+v", rows)
	for _, want := range []string{"9 min ago", "12 files sent", "3 files changed since"} {
		assert.Containsf(t, rows[1].Detail, want, "detail %q missing %q", rows[1].Detail, want)
	}

	rows, _, _ = familyRows("F", probes,
		familyUpload{recorded: true, at: now, failed: 2}, now, false)
	if rows[1].Sev != SevWarn || rows[1].Fix == "" {
		t.Errorf("failed uploads must warn with a fix: %+v", rows[1])
	}
	assert.Containsf(t, rows[1].Detail, "nothing new", "zero shipped should read as checked/nothing new: %q", rows[1].Detail)

	rows, _, _ = familyRows("F", probes, familyUpload{}, now, true)
	assert.Lenf(t, rows, 1, "no record and nothing pending should add no sub-row: %+v", rows)
}

func TestClaudeHeadline(t *testing.T) {
	cand := func(rel string) sources.Candidate { return sources.Candidate{RelPath: rel} }
	probes := []sourceProbe{
		{src: config.ResolvedSource{Source: sources.Source{ID: "claude-code-transcripts", Family: "claude-code"}, Enabled: true},
			d: sources.Discovery{Health: sources.Collected, Sniff: sources.SniffOK, Candidates: []sources.Candidate{
				cand("projects/alpha/a.jsonl"),
				cand("projects/alpha/b.jsonl"),
				cand("projects/beta/c.jsonl"),
				cand("projects/beta/c.meta.json"), // join metadata, not a session
			}}},
		{src: config.ResolvedSource{Source: sources.Source{ID: "claude-code-settings", Family: "claude-code"}, Enabled: true},
			d: sources.Discovery{Health: sources.Collected, Sniff: sources.SniffOK, Candidates: make([]sources.Candidate, 2)}},
	}
	got := claudeHeadline(probes, true)
	want := "3 sessions in 2 projects, plus settings"
	assert.Equalf(t, want, got, "claudeHeadline = %q, want %q", got, want)

	assert.Equal(t, "", claudeHeadline([]sourceProbe{{src: config.ResolvedSource{Source: sources.Source{ID: "codex-rollouts", Family: "codex"}}}}, true))
}

func TestHumanCount(t *testing.T) {
	cases := map[int]string{0: "0", 42: "42", 999: "999", 1000: "1,000", 6873: "6,873", 1234567: "1,234,567"}
	for n, want := range cases {
		assert.Equal(t, HumanCount(n), want)
	}
}

func TestAccountInspectionIsNeutral(t *testing.T) {
	src := config.ResolvedSource{Source: sources.Source{ID: "codex-account", Family: "codex", Gather: "account"}, Root: t.TempDir(), Enabled: true}
	d, err := sources.Discover(sources.Request{Source: src})
	require.NoError(t, err)
	for _, verbose := range []bool{false, true} {
		rows, collecting, files := familyRows("Codex", []sourceProbe{{src: src, d: d}}, familyUpload{}, time.Now(), verbose)
		require.Truef(t, !collecting && files == 0 && len(rows) == 1 && rows[0].Sev == SevDim && rows[0].Detail == "configured; checked during collection", "unexpected account inspection: %+v collecting=%v files=%d", rows, collecting, files)
	}
	rows := discoveryRows(src, d)
	require.Truef(t, len(rows) == 1 && rows[0].Sev == SevDim && rows[0].Detail == d.Reason && rows[0].Fix == "", "unexpected source inspection: %+v", rows)
}

// The run recovers on its own, so the row explains the coming re-ship rather than ordering a reset.
func TestStateRowsNameAnInstallMismatch(t *testing.T) {
	const mine, theirs = "c033b5b2-c3ac-4f39-911f-7ea632b7727c", "85a7e04c-32a4-4bf5-9c80-49c4f9d087bb"
	doc := engine.Document{InstallID: theirs, Entries: map[engine.Key]engine.Fingerprint{}}

	rows := stateRowsFrom(doc, nil, mine)
	i := slices.IndexFunc(rows, func(r Row) bool { return r.Sev == SevWarn })
	require.True(t, i >= 0, "a document written by another install produced no warning")
	found := rows[i]
	assert.Truef(t, strings.Contains(found.Detail, theirs) && strings.Contains(found.Detail, mine), "detail %q must name both installs", found.Detail)
	assert.Containsf(t, found.Detail, "discards it", "detail %q must say the next run recovers by itself", found.Detail)
	assert.NotContainsf(t, found.Detail, "refused", "detail %q still claims runs are blocked", found.Detail)
	assert.Containsf(t, found.Fix, "state reset", "fix %q must name the command that does it sooner", found.Fix)

	// Matching ids, or no identity to compare against, never warn.
	for _, row := range append(stateRowsFrom(engine.Document{InstallID: mine}, nil, mine), stateRowsFrom(doc, nil, "")...) {
		assert.NotEqualf(t, SevWarn, row.Sev, "warned: %+v", row)
	}
}

func seedFailures(t *testing.T, dir string, streak int, events ...formats.FailureEvent) {
	t.Helper()
	rec := formats.FailureRecord{ConsecutiveFailures: streak}
	for _, e := range events {
		rec.Append(e)
	}
	require.NoError(t, writeFailureRecord(dir, rec))
}

func event(at time.Time, kind, message string) formats.FailureEvent {
	return formats.FailureEvent{At: at.Format(time.RFC3339), Kind: kind, Message: message}
}

// Nineteen consecutive failed ticks used to leave doctor entirely green.
func TestFailureRowsContract(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 17, 13, 0, 0, 0, time.UTC)

	require.Nil(t, failureRows(dir, now), "a store with no failure record produces no row")

	seedFailures(t, dir, 19, event(now.Add(-15*time.Minute), formats.FailureTick,
		"state: document belongs to a different install"))
	rows := failureRows(dir, now)
	require.Lenf(t, rows, 1, "got %d rows, want 1", len(rows))
	got := rows[0]
	assert.Equalf(t, SevWarn, got.Sev, "severity = %v, want SevWarn", got.Sev)
	assert.Containsf(t, got.Detail, "19", "detail %q must count the failed runs", got.Detail)
	assert.Containsf(t, got.Fix, "different install", "fix %q must carry the reason the runs failed", got.Fix)

	seedFailures(t, dir, 0)
	assert.Nil(t, failureRows(dir, now), "a healthy install produces no row")

	// An uncounted update must not displace the cause or date of a failing streak.
	seedFailures(t, dir, 5,
		event(now.Add(-30*time.Minute), formats.FailureTick,
			"the run shipped nothing: all 3 attempted uploads failed: connection refused"),
		event(now.Add(-1*time.Minute), formats.FailureUpdate, "self-update from v1.2.3 did not happen"))

	rows = failureRows(dir, now)
	require.Lenf(t, rows, 1, "got %d rows, want 1", len(rows))
	assert.NotContainsf(t, rows[0].Fix, "self-update", "fix %q blamed an uncounted event for the streak", rows[0].Fix)
	assert.Containsf(t, rows[0].Fix, "connection refused", "fix %q lost the reason the runs actually failed", rows[0].Fix)
	assert.Containsf(t, rows[0].Detail, "30 min ago", "detail %q dated the streak from an uncounted event", rows[0].Detail)

	// Once every counted event is evicted, keep the streak without inventing a cause.
	seedFailures(t, dir, 3, event(now, formats.FailureUpdate, "update failed"))

	rows = failureRows(dir, now)
	require.Lenf(t, rows, 1, "got %d rows, want 1", len(rows))
	assert.NotContainsf(t, rows[0].Fix, "update failed", "fix %q fell back to an uncounted event", rows[0].Fix)
}

// Recovered failures appear only in verbose output; ongoing failures already have a schedule row.
func TestLastFailureRows(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	if rows := lastFailureRows(dir, now, true); rows != nil {
		t.Fatalf("a clean install shows no failure row, got %+v", rows)
	}

	r := &Runtime{eff: &config.Effective{StateDir: dir}}
	r.JudgeTick(errors.New("the sink refused"), formats.Report{}, false, platform.Delta{})

	for _, verbose := range []bool{false, true} {
		if rows := lastFailureRows(dir, now, verbose); rows != nil {
			t.Fatalf("an ongoing streak already has a schedule row, got duplicate %+v", rows)
		}
	}

	r.JudgeTick(nil, formats.Report{Shipped: 1}, false, platform.Delta{})
	if rows := lastFailureRows(dir, now, false); rows != nil {
		t.Fatalf("a recovered failure must not warn by default, got %+v", rows)
	}
	rows := lastFailureRows(dir, now, true)
	require.Truef(t, len(rows) == 1 && rows[0].Sev == SevDim && strings.Contains(rows[0].Detail, "tick_failed"), "verbose must still show the recovered failure, got %+v", rows)
}
