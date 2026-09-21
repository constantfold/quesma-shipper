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

func TestNoShippedByteCarriesASeededSecret(t *testing.T) {
	// The one failure here that is a disaster rather than a bug, so it goes first.
	w := stageWorld(t)
	username := realUsername(t)
	stageClaude(t, w, username)
	runOneShot(t)

	for _, o := range collect(t, w) {
		for _, secret := range []string{seededGitHubToken, seededAWSKey, seededShapelessSecret} {
			assert.NotContainsf(t, string(o.Payload), secret, "%s: a seeded secret survived redaction: %s", o.Key, secret)
		}
	}
}

// The counts are the product: a redaction rule widened to catch "tokens" would take every usage
// figure with it while the run looked healthy.
func TestTokenCountsSurviveRedaction(t *testing.T) {
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))
	runOneShot(t)

	var seen bool
	for _, o := range bySourceID(mirrorObjects(collect(t, w)), claudeSource) {
		for _, want := range []string{`"input_tokens":120`, `"output_tokens":340`, `"cache_read_input_tokens":9000`} {
			if strings.Contains(string(o.Payload), want) {
				seen = true
			} else if strings.Contains(string(o.Payload), "input_tokens") {
				t.Errorf("%s: usage numbers were altered; wanted %s", o.Key, want)
			}
		}
	}
	require.True(t, seen, "no usage numbers in any shipped payload; this test would pass vacuously")
}

func TestNoShippedByteCarriesTheOSUsername(t *testing.T) {
	w := stageWorld(t)
	username := realUsername(t)
	stageClaude(t, w, username)
	runOneShot(t)

	objects := mirrorObjects(collect(t, w))
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

func TestEveryObjectCarriesBothHashesAndItsOwnPayload(t *testing.T) {
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))
	runOneShot(t)

	for _, o := range mirrorObjects(collect(t, w)) {
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
}

func TestSealedAtIsAReadableTimeFromThisRun(t *testing.T) {
	// Not pinned, since app takes it from time.Now(), but a field nothing checks is one that can
	// quietly become empty.
	before := time.Now().UTC().Add(-time.Second)
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))
	runOneShot(t)
	after := time.Now().UTC().Add(time.Second)

	for _, o := range collect(t, w) {
		got, err := time.Parse(time.RFC3339, o.Manifest.SealedAt)
		if err != nil {
			t.Errorf("%s: sealed_at %q does not parse: %v", o.Key, o.Manifest.SealedAt, err)
			continue
		}
		if got.Before(before) || got.After(after) {
			t.Errorf("%s: sealed_at %s is outside this run (%s..%s)", o.Key, got, before, after)
		}
	}
}

func TestASecondRunShipsNothing(t *testing.T) {
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))
	firstOut := runOneShot(t)
	require.Equalf(t, 1, countOf(shippedFromLog(t, w), claudeSource), "the first run did not ship the transcript; the rest would pass vacuously:\n%s", firstOut)

	secondOut := runOneShot(t)
	assert.Equal(t, 0, countOf(shippedFromLog(t, w), claudeSource))
	assert.NotEqualf(t, 0, summary(t, secondOut)["unchanged"], "nothing was reported unchanged:\n%s", secondOut)
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

// The shipper rewrites its own project map every run and reads it straight back, so an otherwise
// idle run still moves bytes: counting those would put the throughput line under every summary.
func TestAnIdleSyncPrintsNoThroughputLine(t *testing.T) {
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))

	require.Contains(t, runOneShot(t), "sealed of")
	assert.NotContains(t, runOneShot(t), "sealed of")
}

// The console is budgeted and the log is not, so the log is only worth falling back to if
// everything is in it.
func TestEveryShippedLineLandsInTheRunLog(t *testing.T) {
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))
	out := runOneShot(t)

	console := shippedSources(out)
	require.NotEqual(t, 0, len(console), "the run shipped nothing; the rest of this test would pass vacuously")
	logged := runLogLines(t, w)
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "[") {
			continue
		}
		if !slices.Contains(logged, line) {
			t.Errorf("a per-file line never reached the run log:\n%s\nlog:\n%s",
				line, strings.Join(logged, "\n"))
		}
	}
}

// One fixed name, truncated as it opens: the file answers "what did the last sync do" and an
// appending log would answer a different question at unbounded length.
func TestTheRunLogIsTruncatedEachSync(t *testing.T) {
	w := stageWorld(t)
	stageClaude(t, w, realUsername(t))
	runOneShot(t)
	first := runLogLines(t, w)
	require.Equalf(t, 1, countOf(shippedSources(strings.Join(first, "\n")), claudeSource), "the first sync did not log the transcript; the rest would pass vacuously:\n%s", strings.Join(first, "\n"))

	// A second sync over unchanged input says nothing, so that line can only be the first run's.
	runOneShot(t)
	second := runLogLines(t, w)
	assert.Equal(t, 0, countOf(shippedSources(strings.Join(second, "\n")), claudeSource))
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
