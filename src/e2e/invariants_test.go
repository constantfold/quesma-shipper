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

// These checks inspect one unchanged fixture; only the final subtest starts a second sync.
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
			// Both shapes the stores use, and from the manifest's native_path as well as the payload.
			assert.NotContainsf(t, string(o.Payload), username, "%s: the OS username survived in the payload", o.Key)
			assert.NotContains(t, o.Manifest.NativePath, username)
			// Only where the fixture planted one: the sidecar's native path is the state directory,
			// which sits under home on a real machine but not here.
			if isTranscript(o) && !strings.Contains(o.Manifest.NativePath, "__USER__") {
				t.Errorf("%s: native_path carries no placeholder: %s", o.Key, o.Manifest.NativePath)
			}
		}
	})
	t.Run("EveryObjectCarriesBothHashesAndItsOwnPayload", func(t *testing.T) {
		for _, o := range mirrorObjects(collected) {
			assert.NotEqual(t, "", o.Manifest.SourceHash)
			// An empty shipped_hash once shipped in every object, unnoticed because Seal took the
			// manifest by value.
			assert.NotEqual(t, "", o.Manifest.ShippedHash)
			if o.Manifest.SourceHash == o.Manifest.ShippedHash && o.Manifest.Redaction != nil &&
				o.Manifest.Redaction.Density > 0 {
				t.Errorf("%s: redaction changed bytes but both hashes are equal", o.Key)
			}
			assert.Equal(t, int64(len(o.Payload)), o.Manifest.PayloadSize)
		}
	})
	t.Run("SealedAtIsAReadableTimeFromThisRun", func(t *testing.T) {
		for _, o := range collected {
			got, err := time.Parse(time.RFC3339, o.Manifest.SealedAt)
			if err != nil {
				t.Errorf("%s: sealed_at %q does not parse: %v", o.Key, o.Manifest.SealedAt, err)
				continue
			}
			if got.Before(before) || got.After(after) {
				t.Errorf("%s: sealed_at %s is outside this run (%s..%s)", o.Key, got, before, after)
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
		require.Equal(t, 1, countOf(shippedFromLog(t, w), claudeSource), firstOut)
		require.Contains(t, firstOut, "sealed of")
		secondOut := runOneShot(t)
		assert.Equal(t, 0, countOf(shippedFromLog(t, w), claudeSource), "the new run log must not retain the first sync's upload")
		assert.NotZero(t, summary(t, secondOut)["unchanged"], secondOut)
		assert.NotContains(t, secondOut, "sealed of")
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
		assert.NotEqual(t, name, hexPart)
		if _, err := hex.DecodeString(hexPart); err != nil {
			t.Errorf("%s: name is not hex: %v", o.Key, err)
		}
		for _, leak := range []string{username, "demo", ".jsonl", "projects", cursorConv} {
			assert.NotContains(t, hexPart, leak)
		}
		assert.Truef(t, strings.HasPrefix(o.Key, w.KeyRoot+"/"), "%s: outside this install's subtree %s", o.Key, w.KeyRoot)
	}
}

func TestTouchingEveryFileShipsNothing(t *testing.T) {
	// mtime is a pre-filter and the content hash is the authority: a Cursor session leaves
	// hundreds of files with new mtimes and identical bytes.
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))
	runOneShot(t)

	touchEverything(t, w)
	out := runOneShot(t)

	assert.Equal(t, 0, countOf(shippedFromLog(t, w), claudeSource), out)
}

func TestAppendingOneLineShipsTheFileAgain(t *testing.T) {
	w := stageWorld(t)
	path := stageClaude(t, w, realUsername(t))
	runOneShot(t)
	first := mirrorObjects(collect(t, w))

	appendLine(t, path, `{"type":"user","uuid":"u3","message":{"role":"user","content":[{"type":"text","text":"one more"}]}}`)
	runOneShot(t)
	assert.Equal(t, 1, countOf(shippedFromLog(t, w), claudeSource))
	second := mirrorObjects(collect(t, w))

	// A grown file keeps its key, an HMAC over the path, so growth shows up as a second version
	// rather than a second object.
	require.Lenf(t, second, len(first), "append produced %d objects, want the same %d under new content", len(second), len(first))
	first = slices.DeleteFunc(first, func(o object) bool { return o.Manifest.SourceID != claudeSource })
	second = slices.DeleteFunc(second, func(o object) bool { return o.Manifest.SourceID != claudeSource })
	require.Truef(t, len(first) == 1 && len(second) == 1, "want one transcript before and after append, got %d and %d", len(first), len(second))
	assert.Equal(t, 2, w.store.versions(second[0].Key))
	assert.NotEqual(t, first[0].Manifest.SourceHash, second[0].Manifest.SourceHash, "the transcript grew and source_hash did not move")
	assert.Contains(t, string(second[0].Payload), "one more", "the appended line is not in the shipped payload")
}

func TestCursorPairYieldsADerivedObjectAndKeepsTheRaw(t *testing.T) {
	w := stageWorld(t)
	username := realUsername(t)
	stageCursor(t, w, username, cursorConversation2026_07(), true)
	runOneShot(t)

	objects := bySourceID(mirrorObjects(collect(t, w)), cursorSource)
	require.Lenf(t, objects, 2, "want two objects — the raw transcript and the derived join — got %d", len(objects))

	var raw, derived *object
	for i := range objects {
		if objects[i].Manifest.Derived {
			derived = &objects[i]
		} else {
			raw = &objects[i]
		}
	}
	require.True(t, raw != nil && derived != nil, "want exactly one raw object and one derived object")
	assert.Equalf(t, "ok", derived.Manifest.EnrichStatus, "derived object reports enrich_status %q, want ok", derived.Manifest.EnrichStatus)
	assert.NotEqual(t, 0, len(derived.Manifest.DerivedFrom), "the derived object does not name what it came from")
	// The point of the join: the store holds the tool output and the transcript does not. Passing
	// for the raw object too would mean the enricher no longer earns its cost.
	const onlyInTheStore = "main.go"
	assert.Containsf(t, string(derived.Payload), onlyInTheStore, "the derived payload lacks what only the store has (%q)", onlyInTheStore)
	assert.NotContainsf(t, string(raw.Payload), onlyInTheStore, "the raw transcript already had %q — this fixture no longer tests the join", onlyInTheStore)
}

func TestATranscriptTheStoreDoesNotKnowShipsRawAndSaysSo(t *testing.T) {
	// The drift case: when the join stops aligning, the raw transcript must still ship and the
	// manifest must say the join failed. Silence would be data loss that looks like success.
	w := stageWorld(t)
	username := realUsername(t)
	stageCursor(t, w, username, cursorConversation2026_07(), false)
	runOneShot(t)

	objects := bySourceID(mirrorObjects(collect(t, w)), cursorSource)
	require.Lenf(t, objects, 1, "want the raw transcript alone, got %d objects", len(objects))
	assert.True(t, !objects[0].Manifest.Derived, "a derived object was produced from a store that knows nothing about it")
	assert.NotEqual(t, 0, len(objects[0].Payload), "the raw transcript shipped empty")
}

// The log belongs to whichever sync holds the lock. A manual sync during a scheduled one is
// refused rather than interleaved, and must leave the running run's log where the notice said.
func TestASyncRefusedForTheLockDoesNotTouchTheRunLog(t *testing.T) {
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))
	runOneShot(t)
	before := runLogLines(t, w)

	// Empty install id, so this stands in for another process rather than opening as this install.
	held, err := state.Open(filepath.Join(w.State, "trajectory-shipper"), "")
	require.NoErrorf(t, err, "could not stand in for a running sync: %v", err)
	defer held.Close()

	if out, err := runOneShotExpectingFailure(t, "--quiet"); err == nil {
		t.Fatalf("a second sync was not refused for the lock:\n%s", out)
	}

	if after := runLogLines(t, w); !slices.Equal(before, after) {
		t.Errorf("the refused sync rewrote the running sync's log:\nbefore:\n%s\nafter:\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
}

// --quiet is for cron: it drops the console output and keeps the log, the run's only record.
func TestAQuietSyncStillWritesTheRunLog(t *testing.T) {
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))

	out := runOneShot(t, "--quiet")
	assert.NotContainsf(t, out, "shipped", "--quiet printed a summary:\n%s", out)
	logged := runLogLines(t, w)
	require.NotEqual(t, 0, len(logged), "a quiet sync wrote an empty run log")
	var shippedLines int
	for _, line := range logged {
		if strings.Contains(line, "  shipped (") {
			shippedLines++
		}
	}
	assert.NotEqual(t, 0, shippedLines)
}

func TestADisabledSourceShipsNothing(t *testing.T) {
	w := stageWorld(t)
	username := realUsername(t)
	stageClaude(t, w, username)
	stageCursor(t, w, username, cursorConversation2026_07(), true)
	writeConfig(t, w, "sources:\n  - id: cursor-transcripts\n    enabled: false\n")

	runOneShot(t)

	assert.Len(t, bySourceID(mirrorObjects(collect(t, w)), cursorSource), 0)
	assert.NotEqual(t, 0, len(bySourceID(mirrorObjects(collect(t, w)), claudeSource)), "disabling one source silenced another")
}

func TestThePauseSwitchStopsCollection(t *testing.T) {
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))
	run(t, "pause", "1h")

	require.Len(t, mirrorObjects(collect(t, w)), 0)
	runOneShot(t)
	require.Len(t, mirrorObjects(collect(t, w)), 0)

	run(t, "resume")
	runOneShot(t)
	assert.NotEqual(t, 0, countOf(shippedFromLog(t, w), claudeSource), "resumed, and nothing was collected")
}
