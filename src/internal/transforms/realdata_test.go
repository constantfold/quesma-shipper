package transforms

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRealDataRescrub replays the scrubber over a decrypted archive mirror (SCRUB_REALDATA_DIR,
// payloads plus <payload>.manifest.json sidecars). The mirror is POST-scrub, so this measures
// idempotency at scale: any new hit wants eyeballs.
func TestRealDataRescrub(t *testing.T) {
	root := os.Getenv("SCRUB_REALDATA_DIR")
	if root == "" {
		t.Skip("set SCRUB_REALDATA_DIR to a decrypted mirror to run the real-data replay")
	}

	// No username: the mirror already carries __USER__, and one here would give byte-diffs two meanings.
	s, err := New(DefaultConfig())
	require.NoError(t, err)

	var objects, skipped, changed, engineErrs, filesWithNewHits int
	recordedHits, rescrubHits := map[string]int{}, map[string]int{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".manifest.json") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var m struct {
			SourceFamily string            `json:"source_family"`
			Redaction    *RedactionSummary `json:"redaction"`
		}
		payloadPath := strings.TrimSuffix(path, ".manifest.json")
		payload, readErr := os.ReadFile(payloadPath)
		if json.Unmarshal(raw, &m) != nil || m.Redaction == nil || readErr != nil {
			skipped++
			return nil
		}

		objects++
		for rule, n := range m.Redaction.RuleHits {
			recordedHits[rule] += n
		}
		res, err := s.Scrub(payload, Hint{Family: m.SourceFamily, JSONL: m.Redaction.ScanMode != ScanModeRawText})
		if err != nil {
			engineErrs++
			return nil
		}
		if string(res.Out) != string(payload) {
			changed++
		}
		if len(res.RuleHits) > 0 {
			filesWithNewHits++
			for rule, n := range res.RuleHits {
				rescrubHits[rule] += n
			}
			if filesWithNewHits <= 20 {
				t.Logf("sample: %s %v\n  %s", payloadPath, res.RuleHits, firstDiffLine(string(payload), string(res.Out)))
			}
		}
		return nil
	})
	require.NoError(t, err)

	t.Logf("objects rescrubbed: %d (skipped %d, engine errors %d)", objects, skipped, engineErrs)
	t.Logf("recorded hits in manifests (historical): %v", recordedHits)
	t.Logf("hits on rescrub (should be ~0): %v", rescrubHits)
	t.Logf("objects changed by rescrub: %d of %d; objects with new hits: %d", changed, objects, filesWithNewHits)
}

func firstDiffLine(before, after string) string {
	b, a := strings.Split(before, "\n"), strings.Split(after, "\n")
	for i := range b {
		if i >= len(a) || b[i] != a[i] {
			got := ""
			if i < len(a) {
				got = a[i]
			}
			return b[i][:min(len(b[i]), 160)] + "\n  -> " + got[:min(len(got), 160)]
		}
	}
	return "(no line diff)"
}
