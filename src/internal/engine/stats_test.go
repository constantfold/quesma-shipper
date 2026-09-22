package engine_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// Every run closes its clock and totals its bytes, after the store flush.
func TestARunReportsItsFinishTimeAndItsBytes(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/a.jsonl", line1)
	f.writeTranscript("p/b.jsonl", line1+line2)

	rep := f.run()

	require.True(t, !rep.FinishedAt.IsZero(), "the run left no finish time; every rate the CLI prints divides by it")
	assert.Truef(t, !rep.FinishedAt.Before(rep.StartedAt), "finished %s before it started %s", rep.FinishedAt, rep.StartedAt)
	assert.NotEqual(t, int64(0), rep.BytesRead, "two transcripts were read and BytesRead is zero")
	assert.NotEqual(t, int64(0), rep.BytesSealed, "two transcripts shipped and BytesSealed is zero")
	assert.NotEqual(t, int64(0), rep.MedianFileBytes, "two files shipped and there is no median")
	assert.Truef(t, rep.BytesRead >= rep.MedianFileBytes, "the median file (%d B) is larger than everything read (%d B)", rep.MedianFileBytes, rep.BytesRead)

	// A run that stopped early still says how long it ran: a zero clock drops the CLI's line.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := engine.Run(ctx, f.store, f.opts())
	require.Error(t, err, "a cancelled run returned no error")
	assert.False(t, rep.FinishedAt.IsZero(), "a cancelled run left no finish time")
}
