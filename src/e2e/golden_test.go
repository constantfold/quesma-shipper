package e2e

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Goldens for collected transcripts, narrow on purpose: the key (an HMAC over the home-relative path)
// is recorded, the source digest (over bytes carrying the OS username) is not. A golden diff claims
// the output SHOULD change: read it before running `go test ./e2e -update`.
var update = flag.Bool("update", false, "rewrite the golden files from this run")

// The recorded layout of one object, in reading order.
type goldenObject struct {
	Key           string `json:"key"`
	SourceID      string `json:"source_id"`
	SourceFamily  string `json:"source_family,omitempty"`
	ArtifactClass string `json:"artifact_class"`
	Gather        string `json:"gather"`
	NativePath    string `json:"native_path"`
	ShapeSniff    string `json:"shape_sniff,omitempty"`

	SourceHash   string `json:"source_hash"`
	ShippedHash  string `json:"shipped_hash"`
	PayloadSize  int64  `json:"payload_size"`
	PayloadLines int    `json:"payload_lines"`
	PayloadMTime string `json:"payload_mtime,omitempty"`

	Redaction *goldenRedaction `json:"redaction,omitempty"`

	Derived          bool     `json:"derived,omitempty"`
	Enricher         string   `json:"enricher,omitempty"`
	DerivedFrom      []string `json:"derived_from,omitempty"`
	EnrichStatus     string   `json:"enrich_status,omitempty"`
	EnrichMismatches int      `json:"enrich_mismatches,omitempty"`

	// enrich_status stays "ok" for the explained shortfalls; these tell them apart.
	EnrichRepeats          int `json:"enrich_repeats,omitempty"`
	EnrichTail             int `json:"enrich_tail,omitempty"`
	EnrichAmbiguous        int `json:"enrich_ambiguous,omitempty"`
	EnrichLineDecodeErrors int `json:"enrich_line_decode_errors,omitempty"`

	Recipients  []string `json:"recipients,omitempty"`
	PayloadFile string   `json:"payload_file"`
}

// Counts, not density: a ratio over the whole file moves whenever a fixture gains a character.
type goldenRedaction struct {
	Rules map[string]int `json:"rules,omitempty"`
}

func TestGolden(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test exercises UNIX paths, not available on Windows")
	}
	for _, tc := range []struct {
		name  string
		stage func(t *testing.T, w *world, username string)
	}{
		{"claude-2026-07", func(t *testing.T, w *world, u string) { stageClaude(t, w, u) }},
		// A finding, not an endorsement: the card-pan rule eats an all-digit session id; a fix shows here as a diff.
		{"claude-2026-07-numeric-session", func(t *testing.T, w *world, u string) { stageClaudeSession(t, w, u, numericSessionID) }},
		{"cursor-2026-07", func(t *testing.T, w *world, u string) { stageCursor(t, w, u, cursorConversation2026_07(), true) }},
		// The drift case is a contract too: raw ships, the manifest says why.
		{"cursor-2026-07-no-store", func(t *testing.T, w *world, u string) { stageCursor(t, w, u, cursorConversation2026_07(), false) }},
		// A store that deduplicated a re-run: the derived object ships with what it could not enrich.
		{"cursor-2026-07-repeat", func(t *testing.T, w *world, u string) { stageCursor(t, w, u, cursorConversationRepeat(), true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := stageWorld(t)
			username := realUsername(t)
			tc.stage(t, w, username)
			runOneShot(t)

			var got []goldenObject
			payloads := map[string][]byte{}
			for _, o := range mirrorObjects(collect(t, w)) {
				if !isTranscript(o) {
					continue
				}
				g, payload := normalize(o, w, username)
				got = append(got, g)
				payloads[g.PayloadFile] = payload
			}
			require.NotEqual(t, 0, len(got), "nothing was collected; a golden of nothing proves nothing")
			compareGolden(t, tc.name, got, payloads)
		})
	}
}

// Strips everything the environment decides, keeps everything the shipper decides.
func normalize(o object, w *world, username string) (goldenObject, []byte) {
	payload := scrubEnvironment(o.Payload, w, username)

	g := goldenObject{
		Key:           o.Key,
		SourceID:      o.Manifest.SourceID,
		SourceFamily:  o.Manifest.SourceFamily,
		ArtifactClass: o.Manifest.ArtifactClass,
		Gather:        o.Manifest.Gather,
		NativePath:    string(scrubEnvironment([]byte(o.Manifest.NativePath), w, username)),
		ShapeSniff:    o.Manifest.ShapeSniff,

		ShippedHash:  o.Manifest.ShippedHash,
		PayloadSize:  o.Manifest.PayloadSize,
		PayloadLines: len(strings.Split(strings.TrimRight(string(o.Payload), "\n"), "\n")),

		Derived:          o.Manifest.Derived,
		EnrichStatus:     o.Manifest.EnrichStatus,
		EnrichMismatches: o.Manifest.EnrichMismatches,

		EnrichRepeats:          o.Manifest.EnrichRepeats,
		EnrichTail:             o.Manifest.EnrichTail,
		EnrichAmbiguous:        o.Manifest.EnrichAmbiguous,
		EnrichLineDecodeErrors: o.Manifest.EnrichLineDecodeErrors,
	}
	// Over pre-redaction bytes carrying this machine's username, so only its presence is recorded.
	if o.Manifest.SourceHash != "" {
		g.SourceHash = "<SOURCE-HASH>"
	}
	if o.Manifest.PayloadMTime != nil {
		g.PayloadMTime = o.Manifest.PayloadMTime.UTC().Format(time.RFC3339)
	}
	if o.Manifest.Enricher != nil {
		g.Enricher = fmt.Sprintf("%s@%d", o.Manifest.Enricher.ID, o.Manifest.Enricher.Version)
	}
	for _, from := range o.Manifest.DerivedFrom {
		g.DerivedFrom = append(g.DerivedFrom, string(scrubEnvironment([]byte(from), w, username)))
	}
	if r := o.Manifest.Redaction; r != nil && len(r.RuleHits) > 0 {
		g.Redaction = &goldenRedaction{Rules: r.RuleHits}
	}
	if e := o.Manifest.Encryption; e != nil {
		g.Recipients = e.RecipientKeyIDs
	}
	// One file per object, named for its source and key, with the payload's real extension.
	kind := "-"
	if g.Derived {
		kind = "-derived-"
	}
	stem := strings.TrimSuffix(o.Key[strings.LastIndex(o.Key, "/")+1:], ".age")
	g.PayloadFile = g.SourceID + kind + stem[:12] + ".jsonl"
	return g, payload
}

// The harness's temp directories and the account the tests run as, which a golden must not record.
func scrubEnvironment(b []byte, w *world, username string) []byte {
	s := string(b)
	for from, to := range map[string]string{w.Home: "<HOME>", w.State: "<STATE>", w.Config: "<CONFIG>"} {
		s = strings.ReplaceAll(s, from, to)
	}
	if len(username) >= 2 {
		s = strings.ReplaceAll(s, username, "<USER>")
	}
	return []byte(s)
}

// Payloads are files of their own, so a redaction change reads as a text diff.
func compareGolden(t *testing.T, name string, got []goldenObject, payloads map[string][]byte) {
	t.Helper()
	dir := filepath.Join("testdata", "golden", name)
	indexPath := filepath.Join(dir, "objects.json")

	encoded, err := json.MarshalIndent(got, "", "  ")
	require.NoError(t, err)
	encoded = append(encoded, '\n')

	if *update {
		require.NoError(t, os.RemoveAll(dir))
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "payloads"), 0o755))
		require.NoError(t, os.WriteFile(indexPath, encoded, 0o644))
		for file, body := range payloads {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "payloads", file), body, 0o644))
		}
		t.Logf("wrote %s", dir)
		return
	}

	want, err := os.ReadFile(indexPath)
	require.NoErrorf(t, err, "no golden for %s: %v\nrun: go test ./e2e -update", name, err)
	assert.Equal(t, string(want), string(encoded), "golden index %s", indexPath)
	for file, body := range payloads {
		wantBody, err := os.ReadFile(filepath.Join(dir, "payloads", file))
		if assert.NoErrorf(t, err, "no golden payload %s", file) {
			assert.Equal(t, string(wantBody), string(body), "golden payload %s", file)
		}
	}
}
