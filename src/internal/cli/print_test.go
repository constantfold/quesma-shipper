package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// Complete lines pin field order, spacing, reasons, sizes and the lack of a terminator.
func TestProgressLines(t *testing.T) {
	for _, tc := range []struct {
		source      string
		done, total int
		file        formats.FileOutcome
		want        string
	}{
		{"claude-code", 3, 10, formats.FileOutcome{RelPath: "projects/p/a.jsonl", Decision: formats.DecisionUnchanged}, ""},
		{"claude-code", 3, 10, formats.FileOutcome{RelPath: "projects/p/a.jsonl", Decision: formats.DecisionShipped, BytesIn: 465_000, BytesOut: 120_000},
			"[3/10] claude-code  projects/p/a.jsonl  shipped (454.1 KB in, 117.2 KB sealed)"},
		{"codex", 1, 4, formats.FileOutcome{RelPath: "sessions/big.jsonl", Decision: formats.DecisionSkipped, Reason: "over the 100000000 byte limit for this source"},
			"[1/4] codex  sessions/big.jsonl  skipped: over the 100000000 byte limit for this source"},
		{"claude-code", 1, 1, formats.FileOutcome{RelPath: "a.jsonl", Decision: formats.DecisionShipped, BytesIn: 10, BytesOut: 4},
			"[1/1] claude-code  a.jsonl  shipped (10 B in, 4 B sealed)"},
	} {
		assert.Equal(t, tc.want, progressLine(tc.source, tc.done, tc.total, tc.file))
	}
}

func summaryOutput(report formats.Report, adviseDrain bool) string {
	var out bytes.Buffer
	printRunSummary(&out, report, adviseDrain)
	return out.String()
}

// An oversize warning names the source, file, cap and remedy, with the correct singular or plural.
func TestOversizeSummaries(t *testing.T) {
	for _, tc := range []struct {
		source formats.SourceOutcome
		want   []string
	}{
		{formats.SourceOutcome{SourceID: "codex-rollouts", Health: formats.Collected,
			Oversize: 1, OversizeLargest: 412 << 20, OversizeLimit: 256 << 20, OversizeExample: "sessions/2026/08/01/rollout-2026-08-01-abc.jsonl",
		}, []string{"codex-rollouts", "1 file over the", "256.0 MB", "412.0 MB", "rollout-2026-08-01-abc.jsonl"}},
		{formats.SourceOutcome{SourceID: "claude-code-transcripts", Health: formats.Collected,
			Oversize: 3, OversizeLargest: 900 << 20, OversizeLimit: 256 << 20, OversizeExample: "projects/x/big.jsonl",
		}, []string{"claude-code-transcripts", "3 files over the", "256.0 MB", "900.0 MB", "projects/x/big.jsonl"}},
	} {
		out := summaryOutput(formats.Report{Sources: []formats.SourceOutcome{tc.source}}, false)
		for _, want := range append(tc.want, "max_file_bytes") {
			assert.Contains(t, out, want)
		}
		assert.NotContains(t, out, "they will not be", "unactionable wording")
	}
}

// Only a truncated one-shot sync advises a drain, and only when it left a backlog: the daemon
// re-ticks on its own, and truncation on failures has no backlog worth chasing.
func TestOnlyATruncatedSyncWithABacklogIsToldToDrain(t *testing.T) {
	out := summaryOutput(formats.Report{Truncated: true, Shipped: 64}, true)
	assert.Contains(t, out, "max_files_per_run reached")
	assert.Contains(t, out, "run --once --drain")
	assert.NotContains(t, summaryOutput(formats.Report{Truncated: true, Shipped: 64}, false), "--drain")
	assert.NotContains(t, summaryOutput(formats.Report{Truncated: true, Failed: 64}, true), "--drain")
}

// A missing denominator suppresses throughput; a zero duration still preserves the median; a
// paused run says so instead of a summary.
func TestStatsLines(t *testing.T) {
	at := time.Date(2026, 8, 6, 11, 2, 4, 0, time.UTC)
	for _, tc := range []struct {
		report formats.Report
		want   string
	}{
		{formats.Report{StartedAt: at, FinishedAt: at.Add(3400 * time.Millisecond), BytesRead: 5_452_595, BytesSealed: 1_468_006, MedianFileBytes: 215_040},
			"  sent  1.4 MB sealed of 5.2 MB read in 3.4s  (1.5 MB/s, median file 210.0 KB)"},
		{formats.Report{StartedAt: at, FinishedAt: at.Add(time.Second)}, ""},
		{formats.Report{BytesRead: 1 << 20, BytesSealed: 1 << 19}, ""},
		{formats.Report{StartedAt: at, FinishedAt: at, BytesRead: 4096, BytesSealed: 2048, MedianFileBytes: 4096},
			"  sent  2.0 KB sealed of 4.0 KB read in 0ms  (median file 4.0 KB)"},
	} {
		assert.Equal(t, tc.want, statsLine(tc.report))
	}
	paused := summaryOutput(formats.Report{Paused: true, PauseReason: "by hand", StartedAt: at, FinishedAt: at.Add(time.Second), BytesRead: 1 << 20}, false)
	assert.NotContains(t, paused, "sealed of", "a paused run reported throughput")
}

func TestHumanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		850 * time.Millisecond: "850ms", 3400 * time.Millisecond: "3.4s", 59500 * time.Millisecond: "59.5s",
		200 * time.Second: "3m20s", 65 * time.Minute: "1h05m",
	} {
		assert.Equal(t, want, app.HumanDuration(d))
	}
}

// Alarm notes print once, and an informational note about a conversation that shipped is labelled
// as shipped rather than reported as loss; infos alone raise no alarm.
func TestEnrichNotes(t *testing.T) {
	summary := func(src formats.SourceOutcome) string {
		src.SourceID, src.Health = "cursor-transcripts", formats.Collected
		return summaryOutput(formats.Report{Sources: []formats.SourceOutcome{src}}, false)
	}
	out := summary(formats.SourceOutcome{
		EnrichMismatch: 1, EnrichErrors: 1,
		EnrichNotes: []string{"conv-a: 2 transcript events did not align with the store"},
		EnrichInfos: []string{"conv-b: 3 events carried native-only in the derived object"},
	})
	assert.Equal(t, 1, strings.Count(out, "did not align"))
	assert.Contains(t, out, "1 files sent without their database details")
	assert.Contains(t, out, "enrich errors ×1")
	assert.Contains(t, out, "enrich note (shipped)  conv-b: 3 events carried native-only")

	out = summary(formats.SourceOutcome{Enriched: 2, EnrichInfos: []string{"conv-b: 1 event carried native-only in the derived object"}})
	assert.NotContains(t, out, "enrich errors")
	assert.NotContains(t, out, "without their database details")
	assert.Contains(t, out, "carried native-only")
}
