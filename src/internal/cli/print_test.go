package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// Complete lines pin field order, spacing, reasons, sizes and the lack of a terminator.
func TestProgressLines(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		done, total  int
		file         formats.FileOutcome
		want         string
	}{
		{"unchanged", "claude-code", 3, 10,
			formats.FileOutcome{RelPath: "projects/p/a.jsonl", Decision: formats.DecisionUnchanged}, ""},
		{"shipped sizes", "claude-code", 3, 10,
			formats.FileOutcome{RelPath: "projects/p/a.jsonl", Decision: formats.DecisionShipped,
				BytesIn: 465_000, BytesOut: 120_000},
			"[3/10] claude-code  projects/p/a.jsonl  shipped (454.1 KB in, 117.2 KB sealed)"},
		{"skip reason", "codex", 1, 4,
			formats.FileOutcome{RelPath: "sessions/big.jsonl", Decision: formats.DecisionSkipped,
				Reason: "over the 100000000 byte limit for this source"},
			"[1/4] codex  sessions/big.jsonl  skipped: over the 100000000 byte limit for this source"},
		{"single line", "claude-code", 1, 1,
			formats.FileOutcome{RelPath: "a.jsonl", Decision: formats.DecisionShipped, BytesIn: 10, BytesOut: 4},
			"[1/1] claude-code  a.jsonl  shipped (10 B in, 4 B sealed)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, progressLine(tc.source, tc.done, tc.total, tc.file))
		})
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{512, "512 B"},
		{465_000, "454.1 KB"},
		{12_165_120, "11.6 MB"},
	}
	for _, c := range cases {
		assert.Equal(t, app.HumanBytes(c.n), c.want)
	}
}

// An oversize warning names the source, file, cap and remedy, with the correct singular or plural.
func TestOversizeSummaries(t *testing.T) {
	for _, tc := range []struct {
		source formats.SourceOutcome
		want   []string
	}{
		{formats.SourceOutcome{
			SourceID: "codex-rollouts", Health: formats.Collected,
			Oversize: 1, OversizeLargest: 412 << 20, OversizeLimit: 256 << 20,
			OversizeExample: "sessions/2026/08/01/rollout-2026-08-01-abc.jsonl",
		}, []string{"codex-rollouts", "1 file over the", "256.0 MB", "412.0 MB", "rollout-2026-08-01-abc.jsonl"}},
		{formats.SourceOutcome{
			SourceID: "claude-code-transcripts", Health: formats.Collected,
			Oversize: 3, OversizeLargest: 900 << 20, OversizeLimit: 256 << 20,
			OversizeExample: "projects/x/big.jsonl",
		}, []string{"claude-code-transcripts", "3 files over the", "256.0 MB", "900.0 MB", "projects/x/big.jsonl"}},
	} {
		t.Run(tc.source.SourceID, func(t *testing.T) {
			out := summaryOutput(formats.Report{Sources: []formats.SourceOutcome{tc.source}}, false)
			for _, want := range tc.want {
				assert.Contains(t, out, want)
			}
			assert.Contains(t, out, "max_file_bytes", "the warning must say how to collect the file")
			assert.NotContains(t, out, "they will not be", "unactionable wording")
		})
	}
}

// Only a truncated one-shot sync advises a drain, and only when it left a backlog.
func TestATruncatedSyncSaysHowToFlushTheRest(t *testing.T) {
	out := summaryOutput(formats.Report{Truncated: true, Shipped: 64}, true)
	assert.Containsf(t, out, "max_files_per_run reached", "the truncation note is gone:\n%s", out)
	assert.Containsf(t, out, "run --once --drain", "a truncated sync does not say how to flush the rest:\n%s", out)
}

func TestTheDaemonIsNotToldToDrain(t *testing.T) {
	out := summaryOutput(formats.Report{Truncated: true, Shipped: 64}, false)
	assert.NotContainsf(t, out, "--drain", "the daemon re-ticks on its own; advising a manual drain:\n%s", out)
}

// Truncation on FAILURES has no backlog worth chasing.
func TestATruncatedRunThatShippedNothingIsNotToldToDrain(t *testing.T) {
	out := summaryOutput(formats.Report{Truncated: true, Failed: 64}, true)
	assert.NotContainsf(t, out, "--drain", "a run of pure failures was told to drain:\n%s", out)
}

// A missing denominator suppresses throughput; a zero duration still preserves the median.
func TestStatsLines(t *testing.T) {
	at := time.Date(2026, 8, 6, 11, 2, 4, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		report formats.Report
		want   string
	}{
		{"bytes and throughput", formats.Report{
			StartedAt: at, FinishedAt: at.Add(3400 * time.Millisecond),
			BytesRead: 5_452_595, BytesSealed: 1_468_006, MedianFileBytes: 215_040,
		}, "  sent  1.4 MB sealed of 5.2 MB read in 3.4s  (1.5 MB/s, median file 210.0 KB)"},
		{"nothing read", formats.Report{StartedAt: at, FinishedAt: at.Add(time.Second)}, ""},
		{"no finish time", formats.Report{BytesRead: 1 << 20, BytesSealed: 1 << 19}, ""},
		{"zero duration", formats.Report{
			StartedAt: at, FinishedAt: at, BytesRead: 4096, BytesSealed: 2048, MedianFileBytes: 4096,
		}, "  sent  2.0 KB sealed of 4.0 KB read in 0ms  (median file 4.0 KB)"},
	} {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, statsLine(tc.report)) })
	}
}

// A paused run says so instead of a summary; no stats line may imply otherwise.
func TestAPausedRunHasNoStatsLine(t *testing.T) {
	start := time.Date(2026, 8, 6, 11, 2, 4, 0, time.UTC)
	out := summaryOutput(formats.Report{
		Paused: true, PauseReason: "by hand",
		StartedAt: start, FinishedAt: start.Add(time.Second), BytesRead: 1 << 20,
	}, false)
	assert.NotContainsf(t, out, "sealed of", "a paused run reported throughput:\n%s", out)
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{850 * time.Millisecond, "850ms"},
		{3400 * time.Millisecond, "3.4s"},
		{59500 * time.Millisecond, "59.5s"},
		{200 * time.Second, "3m20s"},
		{65 * time.Minute, "1h05m"},
	}
	for _, c := range cases {
		assert.Equal(t, app.HumanDuration(c.d), c.want)
	}
}

// Alarm notes print once, not once per heading, and an informational note about a conversation
// that shipped must not sit under the "DB-side fields lost" banner.
func TestEnrichNotesPrintOnceAndInfosAreNotReportedAsLoss(t *testing.T) {
	out := summaryOutput(formats.Report{
		Sources: []formats.SourceOutcome{{
			SourceID:       "cursor-transcripts",
			Health:         formats.Collected,
			EnrichMismatch: 1,
			EnrichErrors:   1,
			EnrichNotes:    []string{"conv-a: 2 transcript events did not align with the store"},
			EnrichInfos:    []string{"conv-b: 3 events carried native-only in the derived object"},
		}},
	}, false)

	assert.Equal(t, 1, strings.Count(out, "did not align"))
	require.Truef(t, strings.Contains(out, "1 files sent without their database details") && strings.Contains(out, "enrich errors ×1"), "an alarm heading is missing:\n%s", out)
	require.Containsf(t, out, "carried native-only", "the informational note is gone entirely:\n%s", out)
	// The info line names itself as shipped; it must not read as part of the loss block.
	assert.Containsf(t, out, "enrich note (shipped)", "the informational note has no shipped label:\n%s", out)
	if banner := strings.Index(out, "ENRICH MISMATCH"); banner >= 0 {
		alarmBlock := out[banner:strings.Index(out, "carried native-only")]
		assert.NotContainsf(t, alarmBlock, "native-only", "the info note sits inside the alarm block:\n%s", out)
	}
}

// A source whose enrichment raised no alarm prints its infos and nothing else.
func TestInfosAloneRaiseNoBanner(t *testing.T) {
	out := summaryOutput(formats.Report{
		Sources: []formats.SourceOutcome{{
			SourceID:    "cursor-transcripts",
			Health:      formats.Collected,
			Enriched:    2,
			EnrichInfos: []string{"conv-b: 1 event carried native-only in the derived object"},
		}},
	}, false)
	assert.Truef(t, !strings.Contains(out, "ENRICH MISMATCH") && !strings.Contains(out, "enrich errors"), "an info-only run printed an alarm:\n%s", out)
	assert.Containsf(t, out, "carried native-only", "the info line is missing:\n%s", out)
}

func summaryOutput(report formats.Report, adviseDrain bool) string {
	var out bytes.Buffer
	printRunSummary(&out, report, adviseDrain)
	return out.String()
}
