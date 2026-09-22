package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// Only ordinary input files contribute bytes, and only shipped ones contribute to the median.
func TestSummarizeOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		sources              []SourceOutcome
		read, sealed, median int64
	}{
		{"mixed decisions", []SourceOutcome{
			{SourceID: "a", Files: []FileOutcome{
				{Decision: formats.DecisionShipped, BytesIn: 1000, BytesOut: 400},
				{Decision: formats.DecisionShipped, BytesIn: 3000, BytesOut: 900},
				// A content hash reads bytes; a size/mtime skip does not.
				{Decision: formats.DecisionUnchanged, BytesIn: 500},
				{Decision: formats.DecisionUnchanged},
			}},
			{SourceID: "b", Files: []FileOutcome{{Decision: formats.DecisionFailed, BytesIn: 200}}},
		}, 4700, 1300, 3000},
		{"derived objects", []SourceOutcome{{
			SourceID: "cursor-transcripts", Enriched: 1,
			Files: []FileOutcome{
				{Decision: formats.DecisionShipped, RelPath: "sessions/a.jsonl", BytesIn: 1000, BytesOut: 400},
				// Derived payload bytes are not another input file, even when shipped.
				{Decision: formats.DecisionShipped, Derived: true, NativePath: "sessions/a.jsonl", BytesIn: 8000, BytesOut: 2000},
				{Decision: formats.DecisionUnchanged, Derived: true, NativePath: "sessions/b.jsonl", BytesIn: 4000},
			},
		}}, 1000, 400, 1000},
		{"emitted objects", []SourceOutcome{
			// The shipper's own project map must not make an idle machine appear active.
			{SourceID: "project-map", Emitted: true, Files: []FileOutcome{
				{Decision: formats.DecisionShipped, BytesIn: 203, BytesOut: 1100},
			}},
		}, 0, 0, 0},
		{"empty run", nil, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := Report{Sources: tc.sources}
			summarize(&rep)
			assert.Equal(t, tc.read, rep.BytesRead)
			assert.Equal(t, tc.sealed, rep.BytesSealed)
			assert.Equal(t, tc.median, rep.MedianFileBytes)
		})
	}
}
