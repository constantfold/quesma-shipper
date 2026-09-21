package auditlog_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
)

func open(t *testing.T) (*auditlog.Log, string) {
	t.Helper()
	dir := t.TempDir()
	l, err := auditlog.Open(dir)
	require.NoError(t, err)
	return l, filepath.Join(dir, auditlog.FileName)
}

func TestAppendAndTail(t *testing.T) {
	l, path := open(t)

	for _, d := range []auditlog.Decision{
		auditlog.DecisionShipped,
		auditlog.DecisionUnchanged,
		auditlog.DecisionParked,
	} {
		require.NoError(t, l.Append(auditlog.Entry{
			Decision: d,
			SourceID: "claude-code-transcripts",
			File:     "/Users/__USER__/.claude/projects/p/a.jsonl",
			BytesIn:  4096,
			BytesOut: 1200,
			RuleHits: map[string]int{"github-pat": 1},
		}))
	}

	entries, err := auditlog.Tail(path, 0)
	require.NoError(t, err)
	require.Lenf(t, entries, 3, "expected 3 entries, got %d", len(entries))
	assert.Equalf(t, auditlog.DecisionShipped, entries[0].Decision, "order: first entry is %q", entries[0].Decision)
	assert.Equalf(t, auditlog.DecisionParked, entries[2].Decision, "order: last entry is %q", entries[2].Decision)
	assert.True(t, !entries[0].At.IsZero(), "entries must be timestamped")
}

func TestTailLimits(t *testing.T) {
	l, path := open(t)
	for range 10 {
		require.NoError(t, l.Append(auditlog.Entry{Decision: auditlog.DecisionShipped}))
	}
	entries, err := auditlog.Tail(path, 3)
	require.NoError(t, err)
	assert.Lenf(t, entries, 3, "expected 3 entries, got %d", len(entries))
}

// The log is append-only: an entry already on disk is never rewritten, which is what makes it an audit log.
func TestLogIsAppendOnly(t *testing.T) {
	l, path := open(t)

	require.NoError(t, l.Append(auditlog.Entry{Decision: auditlog.DecisionShipped, File: "first"}))
	first, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, l.Append(auditlog.Entry{Decision: auditlog.DecisionShipped, File: "second"}))
	second, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(second), string(first)), "an existing entry was rewritten; the log must only grow")
}

// A reason string that quotes payload is withheld entirely rather than trimmed.
func TestReasonCarryingPayloadIsWithheld(t *testing.T) {
	l, path := open(t)

	require.NoError(t, l.Append(auditlog.Entry{
		Decision: auditlog.DecisionFailed,
		Reason:   `failed on record {"text":"__REDACTED:github-pat__ and more"}`,
	}))
	entries, err := auditlog.Tail(path, 0)
	require.NoError(t, err)
	assert.NotContainsf(t, entries[0].Reason, "__REDACTED:", "a payload-derived reason must be withheld, got %q", entries[0].Reason)
	assert.Containsf(t, entries[0].Reason, "withheld", "the withholding must be visible rather than silent, got %q", entries[0].Reason)
}

// A newline inside a reason would split one record into two, so reasons are flattened.
func TestReasonNewlinesAreFlattened(t *testing.T) {
	l, path := open(t)
	require.NoError(t, l.Append(auditlog.Entry{
		Decision: auditlog.DecisionFailed,
		Reason:   "line one\nline two\r\nline three",
	}))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, 0, strings.Count(strings.TrimRight(string(raw), "\n"), "\n"), "a multi-line reason produced multiple log lines")
	entries, err := auditlog.Tail(path, 0)
	require.NoError(t, err)
	assert.Lenf(t, entries, 1, "expected one entry, got %d", len(entries))
}

func TestOverlongReasonIsTruncated(t *testing.T) {
	l, path := open(t)
	require.NoError(t, l.Append(auditlog.Entry{Decision: auditlog.DecisionFailed, Reason: strings.Repeat("x", 5000)}))
	entries, err := auditlog.Tail(path, 0)
	require.NoError(t, err)
	assert.Truef(t, len(entries[0].Reason) <= 600, "reason not truncated: %d bytes", len(entries[0].Reason))
	assert.Contains(t, entries[0].Reason, "truncated", "truncation should be visible")
}

// A torn last line from a crash must not make the whole log unreadable.
func TestTornLastLineDoesNotBreakTheRead(t *testing.T) {
	l, path := open(t)
	require.NoError(t, l.Append(auditlog.Entry{Decision: auditlog.DecisionShipped, File: "good"}))

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	if _, err := f.WriteString(`{"decision":"shipped","fi`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	entries, err := auditlog.Tail(path, 0)
	require.NoErrorf(t, err, "a torn line must not fail the read: %v", err)
	assert.Truef(t, len(entries) == 1 && entries[0].File == "good", "the complete entry should survive: %v", entries)
}

func TestTailOnMissingLogIsEmptyNotAnError(t *testing.T) {
	entries, err := auditlog.Tail(filepath.Join(t.TempDir(), "nope.log"), 0)
	require.NoErrorf(t, err, "a missing log is not an error: %v", err)
	assert.Lenf(t, entries, 0, "expected no entries, got %d", len(entries))
}

// Entry has no field for a redacted value or for payload content: the discipline is structural.
func TestEntryHasNoContentFields(t *testing.T) {
	l, path := open(t)
	require.NoError(t, l.Append(auditlog.Entry{
		Decision:         auditlog.DecisionShipped,
		File:             "/Users/__USER__/.claude/projects/p/a.jsonl",
		RedactionDensity: 0.012,
		RuleHits:         map[string]int{"aws-secret-key": 4},
		ObjectKey:        "v1/organization=default/install=x/mirror/source=s/abc.age",
	}))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	// The rule id is recorded; the value it matched cannot be, because there is nowhere to put it.
	for _, forbidden := range []string{"content", "payload", "value", "secret\":"} {
		assert.NotContainsf(t, string(raw), forbidden, "log line contains %q: %s", forbidden, raw)
	}
	assert.Contains(t, string(raw), "aws-secret-key", "the rule id should be recorded: it is what makes scrubbing queryable")
}
