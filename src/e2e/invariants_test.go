package e2e

import (
	"encoding/hex"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	state "github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// Written once: a typo in a source id turns an assertion into one that can never fail.
const (
	claudeSource = "claude-code-transcripts"
	cursorSource = "cursor-transcripts"
)

// Invariants, not goldens: each states a property that must hold for any input, so it keeps
// meaning the same thing as the fixtures grow. Goldens live next door.

// These checks inspect one unchanged fixture; only the final subtests start more syncs.
func TestClaudeCollectionContract(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	w := stageWorld(t)
	username := realUsername(t)
	stageClaude(t, w, username)
	firstOut := runOneShot(t)
	after := time.Now().UTC().Add(time.Second)
	collected := collect(t, w)

	t.Run("NoShippedByteCarriesASeededSecret", func(t *testing.T) {
		for _, o := range collected {
			for _, secret := range []string{seededGitHubToken, seededAWSKey, seededShapelessSecret} {
				assert.NotContainsf(t, string(o.Payload), secret, "%s: a seeded secret survived redaction: %s", o.Key, secret)
			}
		}
	})
	t.Run("TokenCountsSurviveRedaction", func(t *testing.T) {
		var seen bool
		for _, o := range bySourceID(mirrorObjects(collected), claudeSource) {
			if !strings.Contains(string(o.Payload), "input_tokens") {
				continue
			}
			seen = true
			for _, want := range []string{`"input_tokens":120`, `"output_tokens":340`, `"cache_read_input_tokens":9000`} {
				assert.Contains(t, string(o.Payload), want, o.Key)
			}
		}
		require.True(t, seen, "no usage numbers in any shipped payload; this test would pass vacuously")
	})
	t.Run("NoShippedByteCarriesTheOSUsername", func(t *testing.T) {
		objects := mirrorObjects(collected)
		require.NotEqual(t, 0, len(objects), "nothing was collected; the rest of this test would pass vacuously")
		for _, o := range objects {
			assert.NotContainsf(t, string(o.Payload), username, "%s: the OS username survived in the payload", o.Key)
			assert.NotContains(t, o.Manifest.NativePath, username)
			// Only transcripts: the sidecar's native path is the state directory, outside this HOME.
			assert.Truef(t, !isTranscript(o) || strings.Contains(o.Manifest.NativePath, "__USER__"),
				"%s: native_path carries no placeholder: %s", o.Key, o.Manifest.NativePath)
		}
	})
	t.Run("EveryObjectCarriesBothHashesAndItsOwnPayload", func(t *testing.T) {
		for _, o := range mirrorObjects(collected) {
			assert.NotEqual(t, "", o.Manifest.SourceHash)
			// An empty shipped_hash once shipped unnoticed, because Seal took the manifest by value.
			assert.NotEqual(t, "", o.Manifest.ShippedHash)
			redacted := o.Manifest.Redaction != nil && o.Manifest.Redaction.Density > 0
			assert.Falsef(t, redacted && o.Manifest.SourceHash == o.Manifest.ShippedHash, "%s: redaction changed bytes but both hashes are equal", o.Key)
			assert.Equal(t, int64(len(o.Payload)), o.Manifest.PayloadSize)
		}
	})
	t.Run("SealedAtIsAReadableTimeFromThisRun", func(t *testing.T) {
		for _, o := range collected {
			got, err := time.Parse(time.RFC3339, o.Manifest.SealedAt)
			if assert.NoErrorf(t, err, "%s: sealed_at %q does not parse", o.Key, o.Manifest.SealedAt) {
				assert.WithinRangef(t, got, before, after, "%s: sealed_at is outside this run", o.Key)
			}
		}
	})
	t.Run("EveryShippedLineLandsInTheRunLog", func(t *testing.T) {
		console := shippedSources(firstOut)
		require.NotEqual(t, 0, len(console), "the run shipped nothing; the rest of this test would pass vacuously")
		logged := runLogLines(t, w)
		for _, line := range strings.Split(firstOut, "\n") {
			if strings.HasPrefix(line, "[") {
				assert.Contains(t, logged, line, "per-file output must also reach the run log")
			}
		}
	})
	t.Run("UnchangedSync", func(t *testing.T) {
		require.Equal(t, 1, shippedClaude(t, w), firstOut)
		require.Contains(t, firstOut, "sealed of")
		secondOut := runOneShot(t)
		assert.Equal(t, 0, shippedClaude(t, w), "the new run log must not retain the first sync's upload")
		assert.NotZero(t, summary(t, secondOut)["unchanged"], secondOut)
		assert.NotContains(t, secondOut, "sealed of")
	})
	// mtime is a pre-filter and the content hash the authority: Cursor touches hundreds of unchanged files.
	t.Run("TouchingEveryFileShipsNothing", func(t *testing.T) {
		touchEverything(t, w)
		out := runOneShot(t)
		assert.Equal(t, 0, shippedClaude(t, w), out)
	})
}

// Objects whose paths came from an agent's own store, the only place a username can appear.
func isTranscript(o object) bool {
	switch o.Manifest.SourceID {
	case "claude-code-transcripts", "cursor-transcripts", "codex-rollouts":
		return true
	}
	return false
}

func TestKeysRevealNothingAboutTheFileTheyName(t *testing.T) {
	w := stageWorld(t)
	username := realUsername(t)
	stageClaude(t, w, username)
	stageCursor(t, w, username, cursorConversation2026_07(), true)
	runOneShot(t)

	for _, o := range mirrorObjects(collect(t, w)) {
		// The source id is deliberately in the clear so a reader can select by source without a
		// key; everything after it must be opaque.
		name := o.Key[strings.LastIndex(o.Key, "/")+1:]
		hexPart := strings.TrimSuffix(name, ".age")
		if name == hexPart {
			t.Errorf("%s: does not end in .age", o.Key)
		}
		if _, err := hex.DecodeString(hexPart); err != nil {
			t.Errorf("%s: name is not hex: %v", o.Key, err)
		}
		for _, leak := range []string{username, "demo", ".jsonl", "projects", cursorConv} {
			if strings.Contains(hexPart, leak) {
				t.Errorf("%s: key leaks %q", o.Key, leak)
			}
		}
		if !strings.HasPrefix(o.Key, w.KeyRoot+"/") {
			t.Errorf("%s: outside this install's subtree %s", o.Key, w.KeyRoot)
		}
	}
}

func TestAppendingOneLineShipsTheFileAgain(t *testing.T) {
	w := stageWorld(t)
	path := stageClaude(t, w, realUsername(t))
	runOneShot(t)
	first := mirrorObjects(collect(t, w))

	appendLine(t, path, `{"type":"user","uuid":"u3","message":{"role":"user","content":[{"type":"text","text":"one more"}]}}`)
	runOneShot(t)
	if got := shippedClaude(t, w); got != 1 {
		t.Errorf("one transcript grew and %d were shipped", got)
	}
	second := mirrorObjects(collect(t, w))

	// A grown file keeps its key, an HMAC over the path, so growth shows up as a second version
	// rather than a second object.
	if len(second) != len(first) {
		t.Fatalf("append produced %d objects, want the same %d under new content",
			len(second), len(first))
	}
	first, second = bySourceID(first, claudeSource), bySourceID(second, claudeSource)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("want one transcript before and after append, got %d and %d", len(first), len(second))
	}
	if got := w.store.versions(second[0].Key); got != 2 {
		t.Errorf("%s has %d versions after one append, want the original and the grown one",
			second[0].Key, got)
	}
	if second[0].Manifest.SourceHash == first[0].Manifest.SourceHash {
		t.Error("the transcript grew and source_hash did not move")
	}
	if !strings.Contains(string(second[0].Payload), "one more") {
		t.Error("the appended line is not in the shipped payload")
	}
}

func TestCursorPairYieldsADerivedObjectAndKeepsTheRaw(t *testing.T) {
	w := stageWorld(t)
	username := realUsername(t)
	stageCursor(t, w, username, cursorConversation2026_07(), true)
	runOneShot(t)

	objects := bySourceID(mirrorObjects(collect(t, w)), cursorSource)
	if len(objects) != 2 {
		t.Fatalf("want two objects — the raw transcript and the derived join — got %d", len(objects))
	}

	var raw, derived *object
	for i := range objects {
		if objects[i].Manifest.Derived {
			derived = &objects[i]
		} else {
			raw = &objects[i]
		}
	}
	if raw == nil || derived == nil {
		t.Fatal("want exactly one raw object and one derived object")
	}
	if derived.Manifest.EnrichStatus != "ok" {
		t.Errorf("derived object reports enrich_status %q, want ok", derived.Manifest.EnrichStatus)
	}
	if len(derived.Manifest.DerivedFrom) == 0 {
		t.Error("the derived object does not name what it came from")
	}
	// The point of the join: the store holds the tool output and the transcript does not. Passing
	// for the raw object too would mean the enricher no longer earns its cost.
	const onlyInTheStore = "main.go"
	if !strings.Contains(string(derived.Payload), onlyInTheStore) {
		t.Errorf("the derived payload lacks what only the store has (%q)", onlyInTheStore)
	}
	if strings.Contains(string(raw.Payload), onlyInTheStore) {
		t.Errorf("the raw transcript already had %q — this fixture no longer tests the join", onlyInTheStore)
	}
}

// The log belongs to whichever sync holds the lock. A manual sync during a scheduled one is
// refused rather than interleaved, and must leave the running run's log where the notice said.
func TestASyncRefusedForTheLockDoesNotTouchTheRunLog(t *testing.T) {
	w := stageClaudeWorld(t)
	runOneShot(t)
	before := runLogLines(t, w)

	// Empty install id, so this stands in for another process rather than opening as this install.
	held, err := state.Open(filepath.Join(w.State, "trajectory-shipper"), "")
	if err != nil {
		t.Fatalf("could not stand in for a running sync: %v", err)
	}
	defer held.Close()

	if out, err := runExpectingFailure(t, "run", "--once", "--quiet"); err == nil {
		t.Fatalf("a second sync was not refused for the lock:\n%s", out)
	}

	if after := runLogLines(t, w); !slices.Equal(before, after) {
		t.Errorf("the refused sync rewrote the running sync's log:\nbefore:\n%s\nafter:\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
}

// --quiet is for cron: it drops the console output and keeps the log, the run's only record.
func TestAQuietSyncStillWritesTheRunLog(t *testing.T) {
	w := stageClaudeWorld(t)

	out := runOneShot(t, "--quiet")
	if strings.Contains(out, "shipped") {
		t.Errorf("--quiet printed a summary:\n%s", out)
	}
	logged := runLogLines(t, w)
	if len(logged) == 0 {
		t.Fatal("a quiet sync wrote an empty run log")
	}
	var shippedLines int
	for _, line := range logged {
		if strings.Contains(line, "  shipped (") {
			shippedLines++
		}
	}
	if shippedLines == 0 {
		t.Errorf("the quiet run's log records nothing it shipped:\n%s", strings.Join(logged, "\n"))
	}
}

func TestADisabledSourceShipsNothing(t *testing.T) {
	w := stageWorld(t)
	username := realUsername(t)
	stageClaude(t, w, username)
	stageCursor(t, w, username, cursorConversation2026_07(), true)
	writeConfig(t, w, "sources:\n  - id: cursor-transcripts\n    enabled: false\n")

	runOneShot(t)

	if got := bySourceID(mirrorObjects(collect(t, w)), cursorSource); len(got) != 0 {
		t.Errorf("a disabled source shipped %d objects", len(got))
	}
	if got := bySourceID(mirrorObjects(collect(t, w)), claudeSource); len(got) == 0 {
		t.Error("disabling one source silenced another")
	}
}

func TestThePauseSwitchStopsCollection(t *testing.T) {
	w := stageClaudeWorld(t)
	run(t, "pause", "1h")

	if got := mirrorObjects(collect(t, w)); len(got) != 0 {
		t.Fatalf("nothing has run yet and %d objects exist", len(got))
	}
	runOneShot(t)
	if got := mirrorObjects(collect(t, w)); len(got) != 0 {
		t.Fatalf("paused, and %d objects were still shipped", len(got))
	}

	run(t, "resume")
	runOneShot(t)
	if got := shippedClaude(t, w); got == 0 {
		t.Error("resumed, and nothing was collected")
	}
}
