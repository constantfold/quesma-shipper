package transforms_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// derivedManifest is manifest() dressed as enricher output, with the fields the schema
// requires of a derived object.
func derivedManifest() transforms.Manifest {
	m := manifest()
	m.ShippedHash = strings.Repeat("b", 64)
	m.Derived = true
	m.Enricher = &transforms.EnricherRef{ID: "cursor-transcript-join", Version: 4}
	m.DerivedFrom = []string{strings.Repeat("a", 64)}
	m.EnrichStatus = "ok"
	return m
}

// Without these keys a derived object with native-only holes is byte-identical in its manifest
// to a fully enriched one.
func TestTheManifestCarriesExplainedEnrichShortfalls(t *testing.T) {
	m := derivedManifest()
	m.EnrichRepeats = 3
	m.EnrichTail = 1
	m.EnrichAmbiguous = 2
	m.EnrichLineDecodeErrors = 4

	raw, err := m.Encode()
	require.NoErrorf(t, err, "encode: %v", err)
	for _, want := range []string{
		`"enrich_repeats":3`, `"enrich_tail":1`, `"enrich_ambiguous":2`,
		`"enrich_line_decode_errors":4`,
	} {
		assert.Containsf(t, string(raw), want, "manifest does not carry %s:\n%s", want, raw)
	}

	back, err := transforms.DecodeManifest(raw)
	require.NoErrorf(t, err, "decode: %v", err)
	assert.Truef(t, back.EnrichRepeats == 3 && back.EnrichTail == 1 && back.EnrichAmbiguous == 2 && back.EnrichLineDecodeErrors == 4, "round trip lost the counts: repeats=%d tail=%d ambiguous=%d lineDecodeErrors=%d", back.EnrichRepeats, back.EnrichTail, back.EnrichAmbiguous, back.EnrichLineDecodeErrors)
}

// A complete object's manifest bytes must not change because counters were added for the
// incomplete ones.
func TestZeroEnrichShortfallsAreOmitted(t *testing.T) {
	raw, err := derivedManifest().Encode()
	require.NoErrorf(t, err, "encode: %v", err)
	for _, absent := range []string{"enrich_repeats", "enrich_tail", "enrich_ambiguous", "enrich_line_decode_errors"} {
		assert.NotContainsf(t, string(raw), absent, "a complete object's manifest mentions %s:\n%s", absent, raw)
	}
}
