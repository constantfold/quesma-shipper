package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	seal "github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// object is one sealed object, opened.
type object struct {
	Key      string
	Manifest seal.Manifest
	Payload  []byte
}

// summary parses the run's own counters ("shipped 4 unchanged 0 ..."). Never count objects in the
// store instead: a re-shipped file lands under the same key, so the key set is identical whether
// the run sent everything or nothing, which is exactly what change detection is about.
func summary(t *testing.T, out string) map[string]int {
	t.Helper()
	counts := map[string]int{}
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "shipped", "unchanged", "skipped", "parked", "failed":
			var n int
			if _, err := fmt.Sscanf(fields[i+1], "%d", &n); err == nil {
				counts[fields[i]] = n
			}
		}
	}
	require.NotEmptyf(t, counts, "no run summary in the output:\n%s", out)
	return counts
}

// The source id of everything the run actually sent, per file. A global "shipped 0" would be both
// too strict and too vague, because the generated project-map sidecar can legitimately change when
// nothing was collected. Change-detection assertions must feed this the run log via shippedFromLog:
// the console truncates to 32 per-file lines, so parsing it directly is only for console tests.
func shippedSources(out string) []string {
	var sources []string
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.HasPrefix(fields[0], "[") && slices.Contains(fields[2:], "shipped") {
			sources = append(sources, fields[1])
		}
	}
	return sources
}

// The log is the complete record, bounded by neither the console budget nor --quiet. A missing
// file fails rather than returning empty, because that is what the tests using it check.
func runLogLines(t *testing.T, w *world) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(statePath(w), "last-sync.log"))
	require.NoErrorf(t, err, "the sync wrote no run log: %v", err)
	return slices.DeleteFunc(strings.Split(string(raw), "\n"), func(line string) bool { return line == "" })
}

// shippedSources over the untruncated run log, so growing a fixture past the console's 32-line
// budget can never turn "nothing re-shipped" into "nothing was printed".
func shippedFromLog(t *testing.T, w *world) []string {
	t.Helper()
	return shippedSources(strings.Join(runLogLines(t, w), "\n"))
}

// How many Claude transcripts the last run shipped, by its log.
func shippedClaude(t *testing.T, w *world) int {
	t.Helper()
	return len(slices.DeleteFunc(shippedFromLog(t, w), func(id string) bool { return id != claudeSource }))
}

// collect opens the current version of every object, sorted by key; the write history behind it is
// fakeStore.versions. Age is nondeterministic, so only the manifest and payload inside are stable.
func collect(t *testing.T, w *world) []object {
	t.Helper()
	current := map[string]storedPut{}
	for _, put := range w.store.stored() {
		current[put.Key] = put
	}
	objects := make([]object, 0, len(current))
	for key, put := range current {
		m, payload, err := seal.Open(put.Body, w.Identity)
		require.NoErrorf(t, err, "%s: open: %v", key, err)
		objects = append(objects, object{Key: key, Manifest: m, Payload: payload})
	}
	slices.SortFunc(objects, func(a, b object) int { return strings.Compare(a.Key, b.Key) })
	return objects
}

// Drops the heartbeat and anything else under state/, which is written on every run regardless.
func mirrorObjects(objs []object) []object {
	return slices.DeleteFunc(slices.Clone(objs), func(o object) bool { return !strings.Contains(o.Key, "/mirror/") })
}

func bySourceID(objs []object, id string) []object {
	return slices.DeleteFunc(slices.Clone(objs), func(o object) bool { return o.Manifest.SourceID != id })
}
