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

func TestConcurrencyTakesThePinAndNeverExceedsTheCandidates(t *testing.T) {
	cases := []struct {
		workers, candidates, want int
	}{
		{3, 100, 3}, // a test pin wins
		{8, 2, 2},   // never more goroutines than files
		{0, 0, 1},   // and never fewer than one
	}
	for _, c := range cases {
		o := Options{Workers: c.workers}
		assert.Equal(t, o.concurrency(c.candidates), c.want)
	}
}

func TestUploadConcurrencyTakesThePin(t *testing.T) {
	assert.Equal(t, 5, (Options{UploadWorkers: 5}).uploadConcurrency(3))
}

func admissionPass(budget int, sizes ...int64) *sourcePass {
	cands := make([]sources.Candidate, len(sizes))
	for i, sz := range sizes {
		cands[i] = sources.Candidate{Size: sz}
	}
	b := budget
	return &sourcePass{budget: &b, disc: sources.Discovery{Candidates: cands}}
}

// Each gate alone: the admission predicate is the whole budget-and-safety policy of the pass.
func TestAdmissionGates(t *testing.T) {
	ctx := context.Background()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	t.Run("budget is reserved by admission", func(t *testing.T) {
		p := admissionPass(1, 1, 1)
		var stopped error
		require.True(t, p.canAdmit(ctx, 0, 0, &stopped), "first admission refused with budget available")
		assert.True(t, !p.canAdmit(ctx, 1, 1, &stopped), "second admission granted on a spent budget")
		assert.Equalf(t, 0, *p.budget, "budget = %d after one admission from 1", *p.budget)
	})

	t.Run("a fatal pass admits nothing", func(t *testing.T) {
		p := admissionPass(10, 1, 1)
		p.fatal = true
		var stopped error
		assert.True(t, !p.canAdmit(ctx, 0, 0, &stopped), "admitted a file after a refusal")
	})

	t.Run("a cancelled context stops admission and says so once", func(t *testing.T) {
		p := admissionPass(10, 1, 1)
		var stopped error
		assert.True(t, !p.canAdmit(cancelled, 0, 0, &stopped), "admitted a file on a dead context")
		assert.Error(t, stopped, "the cancellation was not recorded for the pass to return")
	})

	t.Run("in-flight bytes hold a large file back", func(t *testing.T) {
		p := admissionPass(10, platform.MaxInFlightBytes(), platform.MaxInFlightBytes())
		var stopped error
		require.True(t, p.canAdmit(ctx, 0, 0, &stopped), "first large file refused")
		p.inFlightBytes = p.disc.Candidates[0].Size
		assert.True(t, !p.canAdmit(ctx, 1, 1, &stopped), "two gate-sized files admitted together")
	})

	t.Run("a file larger than the whole gate still runs, alone", func(t *testing.T) {
		p := admissionPass(10, platform.MaxInFlightBytes()*2)
		var stopped error
		assert.True(t, p.canAdmit(ctx, 0, 0, &stopped), "an oversized file was refused outright; it must run with the pass to itself")
	})

	// The gate is read at admission, not baked in at compile time.
	t.Run("the gate follows the environment override", func(t *testing.T) {
		const small = 4 << 20
		t.Cleanup(func() {
			require.NoError(t, platform.ApplyMaxInFlightBytesFromEnv())
		})
		t.Setenv(platform.EnvMaxInFlightBytes, strconv.Itoa(small))
		require.NoError(t, platform.ApplyMaxInFlightBytesFromEnv())

		p := admissionPass(10, small, small)
		var stopped error
		require.True(t, p.canAdmit(ctx, 0, 0, &stopped), "first file refused under the overridden cap")
		p.inFlightBytes = p.disc.Candidates[0].Size
		assert.True(t, !p.canAdmit(ctx, 1, 1, &stopped), "two files admitted together past the overridden cap")
	})
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
				if loads != 0 || result.outcome.Decision != "unchanged" {
					t.Fatalf("reloaded uploaded snapshot: loads=%d, %+v", loads, result.outcome)
				}
			} else if loads != 1 || result.outcome.Decision != "parked" {
				t.Fatalf("did not retry uncommitted snapshot: loads=%d, %+v", loads, result.outcome)
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
	if err := p.run(context.Background()); err != nil || !p.rep.Truncated || p.out.Remaining != 1 {
		t.Fatalf("budget: %+v, %v", p.out, err)
	}
	assert.Nil(t, p.out.Files, "unadmitted candidates have no outcome")
}

func TestAssembleKeepsDecidedSlotsInCandidateOrder(t *testing.T) {
	want := []FileOutcome{
		{Decision: "shipped"}, {Decision: "unchanged"}, {Decision: "skipped"},
		{Decision: "parked"}, {Decision: "failed", Fatal: true},
	}
	p := &sourcePass{out: &SourceOutcome{}}
	for _, outcome := range want {
		p.slots = append(p.slots, FileOutcome{}, outcome)
	}
	p.slots = append(p.slots, FileOutcome{})
	p.assemble()
	assert.Equal(t, want, p.out.Files)
}

func TestBackoffCommitFailurePreservesReadError(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir, "3f2504e0-4f89-41d3-9a0c-0305e82c3301")
	require.NoError(t, err)
	defer store.Close()
	// A directory at the document path makes replacement fail even for a privileged test user.
	require.NoError(t, os.Mkdir(filepath.Join(dir, FileName), 0o700))
	p := &sourcePass{store: newCommitBuffer(store, 1)}
	var result fileResult
	failAndBackOff(Options{Now: time.Now}, &result, Key{SourceID: "s", NativePath: "/session"}, Fingerprint{}, "read denied")
	p.applyIntent(&result)
	assert.Equal(t, "parked", string(result.outcome.Decision))
	assert.Contains(t, result.outcome.Reason, "read denied (and the backoff could not be recorded: ")
}
