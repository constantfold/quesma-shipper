package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

func admissionPass(budget int, sizes ...int64) *sourcePass {
	cands := make([]sources.Candidate, len(sizes))
	for i, sz := range sizes {
		cands[i] = sources.Candidate{Size: sz}
	}
	b := budget
	return &sourcePass{budget: &b, disc: sources.Discovery{Candidates: cands}}
}

// Each check alone: the admission predicate is the whole budget-and-safety policy of the pass.
func TestAdmissionChecks(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	huge := platform.MaxInFlightBytes()
	fatal := admissionPass(10, 1)
	fatal.fatal = true
	for _, tc := range []struct {
		name     string
		p        *sourcePass
		ctx      context.Context
		admitted int // files already in flight, each holding its candidate's bytes
		want     bool
	}{
		{"budget available", admissionPass(1, 1, 1), context.Background(), 0, true},
		{"budget spent", admissionPass(0, 1), context.Background(), 0, false},
		{"a fatal pass admits nothing", fatal, context.Background(), 0, false},
		{"a cancelled context stops admission", admissionPass(10, 1), cancelled, 0, false},
		{"in-flight bytes hold a large file back", admissionPass(10, huge, huge), context.Background(), 1, false},
		{"a file larger than the whole limit still runs, alone", admissionPass(10, huge*2), context.Background(), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := range tc.admitted {
				tc.p.inFlightBytes += tc.p.disc.Candidates[i].Size
			}
			budget := *tc.p.budget
			var stopped error
			assert.Equal(t, tc.want, tc.p.canAdmit(tc.ctx, tc.admitted, tc.admitted, &stopped))
			if tc.want {
				assert.Equal(t, budget-1, *tc.p.budget, "admission reserves one unit of budget")
			}
			assert.Equal(t, tc.ctx.Err() != nil, stopped != nil, "only a cancellation is recorded for the pass to return")
		})
	}

	// The limit is read at admission, not baked in at compile time.
	const small = 4 << 20
	t.Cleanup(func() { require.NoError(t, platform.ApplyMaxInFlightBytesFromEnv()) })
	t.Setenv(platform.EnvMaxInFlightBytes, strconv.Itoa(small))
	require.NoError(t, platform.ApplyMaxInFlightBytesFromEnv())
	p := admissionPass(10, small, small)
	p.inFlightBytes = small
	var stopped error
	assert.False(t, p.canAdmit(context.Background(), 1, 1, &stopped), "two files admitted together past the overridden cap")
}

func TestGeneratedFileChecksUploadStateBeforeLoading(t *testing.T) {
	for _, hash := range []string{"", "uploaded"} {
		t.Run("hash="+hash, func(t *testing.T) {
			loads := 0
			cand := sources.Candidate{Path: "snapshot.jsonl", Size: 1024, MTime: time.Unix(1000, 0), Load: func(context.Context) (sources.Payload, error) {
				loads++
				return sources.Payload{}, errors.New("fixture load failure")
			}}
			o := Options{DryRun: true, Now: time.Now}
			result := o.prepareFile(context.Background(), fileJob{seen: true, fp: Fingerprint{SourceHash: hash, SourceSize: cand.Size, SourceMTime: cand.MTime}},
				sources.Resolved{}, sources.Discovery{Candidates: []sources.Candidate{cand}}, false)
			require.Nil(t, result.pending, "unexpected upload")
			if hash != "" {
				assert.Truef(t, loads == 0 && result.outcome.Decision == "unchanged", "reloaded uploaded snapshot: loads=%d, %+v", loads, result.outcome)
			} else {
				assert.Truef(t, loads == 1 && result.outcome.Decision == "parked", "did not retry uncommitted snapshot: loads=%d, %+v", loads, result.outcome)
			}
		})
	}
}

func TestSpentBudgetDoesNotLoadCandidates(t *testing.T) {
	p := admissionPass(0, 1024)
	p.rep, p.out = &Report{}, &SourceOutcome{}
	p.disc.Candidates[0].Load = func(context.Context) (sources.Payload, error) {
		t.Error("loaded a candidate without an upload slot")
		return sources.Payload{}, nil
	}
	err := p.run(context.Background())
	require.Truef(t, err == nil && p.rep.Truncated && p.out.Remaining == 1, "budget: %+v, %v", p.out, err)
	assert.Nil(t, p.out.Files, "unadmitted candidates have no outcome")
}

func TestBackoffCommitFailurePreservesReadError(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir, "3f2504e0-4f89-41d3-9a0c-0305e82c3301")
	require.NoError(t, err)
	defer store.Close()
	// A directory at the document path makes replacement fail even for a privileged test user.
	require.NoError(t, os.Mkdir(filepath.Join(dir, FileName), 0o700))
	buffer := newCommitBuffer(store, 1)
	result := fileResult{outcome: FileOutcome{SourceID: "s", NativePath: "/session"}}
	failAndBackOff(Options{Now: time.Now}, &result, Fingerprint{}, "read denied")
	buffer.applyIntent(&result)
	assert.Equal(t, "parked", string(result.outcome.Decision))
	assert.Contains(t, result.outcome.Reason, "read denied (and the backoff could not be recorded: ")
}
