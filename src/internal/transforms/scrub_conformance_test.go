package transforms_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

var update = flag.Bool("update", false, "regenerate the conformance vectors (scrub and container)")

const scrubVectorPath = "../../conformance/v1/scrub/redaction.json"

// scrubVectors are before/after pairs as data, so a second-language port is checked against the
// same corpus. Every "after" must contain only sentinels and structural placeholders, never a
// secret, which is what makes this file safe to commit; TestConformanceVectorsCarryNoSecrets
// asserts it rather than assuming it.
type scrubVectors struct {
	VectorSet     string              `json:"vector_set"`
	VectorVersion int                 `json:"vector_version"`
	Description   string              `json:"description"`
	Sentinel      string              `json:"sentinel_form"`
	Username      string              `json:"username"`
	Exemptions    map[string][]string `json:"structural_exempt"`
	Vectors       []scrubVector       `json:"vectors"`
}

type scrubVector struct {
	Name     string         `json:"name"`
	Family   string         `json:"family"`
	JSONL    bool           `json:"jsonl"`
	Before   string         `json:"before"`
	After    string         `json:"after"`
	RuleHits map[string]int `json:"rule_hits"`
	ScanMode string         `json:"scan_mode"`
	Note     string         `json:"note,omitempty"`
}

func TestConformanceRedaction(t *testing.T) {
	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(scrubVectorPath), 0o755))
		require.NoError(t, os.WriteFile(scrubVectorPath, generateScrubVectors(t), 0o644))
		t.Logf("regenerated %s", scrubVectorPath)
	}

	var v scrubVectors
	readVectors(t, scrubVectorPath, &v)
	assert.Equalf(t, transforms.Sentinel("{rule_id}"), v.Sentinel, "sentinel form drifted: vector %q, code %q", v.Sentinel, transforms.Sentinel("{rule_id}"))

	cfg := transforms.DefaultConfig()
	cfg.Exemptions = v.Exemptions
	cfg.Username = v.Username
	s, err := transforms.New(cfg)
	require.NoError(t, err)

	for _, c := range v.Vectors {
		t.Run(c.Name, func(t *testing.T) {
			res, err := s.Scrub([]byte(c.Before), transforms.Hint{Family: c.Family, JSONL: c.JSONL})
			require.NoErrorf(t, err, "engine error: %v", err)
			assert.Equalf(t, c.After, string(res.Out), "output drifted:\n got %q\nwant %q", res.Out, c.After)
			if c.ScanMode != "" && res.ScanMode != c.ScanMode {
				t.Errorf("scan_mode: got %q want %q", res.ScanMode, c.ScanMode)
			}
			for rule, want := range c.RuleHits {
				assert.Equal(t, res.RuleHits[rule], want)
			}
		})
	}
}

// The vector file is committed, so it must not become a place secrets live.
func TestConformanceVectorsCarryNoSecrets(t *testing.T) {
	var v scrubVectors
	readVectors(t, scrubVectorPath, &v)
	for _, c := range v.Vectors {
		for _, planted := range plantedValues() {
			assert.Truef(t, !strings.Contains(c.After, planted), "vector %q records a secret in its AFTER value: %q", c.Name, planted)
		}
	}
}

func plantedValues() []string {
	return []string{
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
		"tOk3nZq8vLmXw2Rf5uJhPd0aYc6eBn1KsG9iD4",
		"4111 1111 1111 1111",
		"hunter2",
		"jane",
	}
}

// Inputs and descriptions live in the committed vectors; regeneration changes only expectations.
func generateScrubVectors(t *testing.T) []byte {
	t.Helper()
	var out scrubVectors
	readVectors(t, scrubVectorPath, &out)
	cfg := transforms.DefaultConfig()
	cfg.Exemptions, cfg.Username = out.Exemptions, out.Username
	s, err := transforms.New(cfg)
	require.NoError(t, err)
	out.Sentinel = transforms.Sentinel("{rule_id}")
	for i := range out.Vectors {
		c := &out.Vectors[i]
		res, err := s.Scrub([]byte(c.Before), transforms.Hint{Family: c.Family, JSONL: c.JSONL})
		require.NoError(t, err)
		c.After, c.RuleHits, c.ScanMode = string(res.Out), res.RuleHits, res.ScanMode
	}
	return encodeVectors(t, out)
}

func readVectors(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, into))
}

func encodeVectors(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	return append(b, '\n')
}
