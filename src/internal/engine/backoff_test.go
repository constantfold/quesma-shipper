package engine_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// An unreadable file must stop consuming the run budget.
func TestAnUnreadableFileBacksOffInsteadOfBurningTheBudgetForever(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/good.jsonl", line1)
	bad := filepath.Join(f.home, ".claude", "projects", "p", "bad.jsonl")
	f.writeTranscript("p/bad.jsonl", line1)
	require.NoError(t, os.Chmod(bad, 0o000))
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
	if _, err := os.ReadFile(bad); err == nil {
		t.Skip("this user can read a mode-000 file")
	}

	first := f.run()
	// Parked, not failed: the entry is held off with a backoff, which the fingerprint records.
	require.Truef(t, first.Parked == 1 && first.Failed == 0, "expected the unreadable file to park once, got %+v", first)

	// Second tick, immediately: inside the backoff the file is skipped rather than read again.
	f.reopen()
	second := f.run()
	assert.Equalf(t, 0, second.Parked, "the unreadable file was read again inside its backoff: %+v", second)
	assert.Equalf(t, 1, second.Skipped, "expected it to be skipped while parked, got %+v", second)
}

// The backoff must expire: there is no attempt limit, because giving up silently loses data.
func TestABackedOffFileIsRetriedOnceTheDelayPasses(t *testing.T) {
	f := newFixture(t)
	// A readable file beside it, or the shape sniff condemns the whole source instead.
	f.writeTranscript("p/good.jsonl", line1)
	bad := filepath.Join(f.home, ".claude", "projects", "p", "bad.jsonl")
	f.writeTranscript("p/bad.jsonl", line1)
	require.NoError(t, os.Chmod(bad, 0o000))
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
	if _, err := os.ReadFile(bad); err == nil {
		t.Skip("this user can read a mode-000 file")
	}

	require.Equal(t, 1, f.run().Parked)
	if err := os.Chmod(bad, 0o600); err != nil { // whatever was wrong is now fixed
		t.Fatal(err)
	}

	// Two hours later: past the one-hour cap on the backoff.
	f.reopen()
	rep := f.runWith(func(o *engine.Options) {
		later := o.Now().Add(2 * time.Hour)
		o.Now = func() time.Time { return later }
	})
	assert.Equalf(t, 1, rep.Shipped, "a file that became readable was not collected after its backoff: %+v", rep)
}

// A park that has been overtaken by events must clear. Otherwise `status` and `doctor` report a
// healthy file as parked for good, while the heartbeat calls the same file unchanged.
func TestAParkedFileStopsBeingParkedOnceItReadsCleanAgain(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/good.jsonl", line1)
	bad := filepath.Join(f.home, ".claude", "projects", "p", "bad.jsonl")
	f.writeTranscript("p/bad.jsonl", line1)

	// Ship it first, so the entry carries the source hash only a completed ship can write.
	require.Equal(t, 2, f.run().Shipped)

	// It changes, so the size-and-mtime pre-filter no longer short-circuits, and it cannot be
	// read: that is what parks it.
	f.writeTranscript("p/bad.jsonl", line1+line2)
	require.NoError(t, os.Chmod(bad, 0o000))
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
	if _, err := os.ReadFile(bad); err == nil {
		t.Skip("this user can read a mode-000 file")
	}
	f.reopen()
	require.Equal(t, 1, f.run().Parked)

	// Readable again, and reverted to the bytes that shipped: the next run past the backoff reads
	// it, matches the committed hash, and ships nothing. The entry must come out clean.
	require.NoError(t, os.Chmod(bad, 0o600))
	f.writeTranscript("p/bad.jsonl", line1)
	f.reopen()
	rep := f.runWith(func(o *engine.Options) {
		later := o.Now().Add(2 * time.Hour)
		o.Now = func() time.Time { return later }
	})
	require.Truef(t, rep.Shipped == 0 && rep.Unchanged == 2, "unchanged bytes should re-ship nothing, got %+v", rep)

	doc, err := engine.Peek(f.stateDir)
	require.NoError(t, err)
	fp, ok := doc.Entries[engine.Key{SourceID: "claude-code-transcripts", NativePath: bad}]
	if !ok {
		t.Fatalf("no entry for %s in %+v", bad, doc.Entries)
	}
	assert.Truef(t, !fp.Parked && fp.LastError == "" && fp.Attempts == 0 && fp.BackoffUntil.IsZero(), "the park survived a clean read: %+v", fp)
}

// A revoked install must fail fast: without the latch every remaining file repeats the same
// refusal and writes a park record, burying the one line that says access was revoked.
func TestARefusedInstallStopsTheRunAtTheFirstFile(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 20; i++ {
		f.writeTranscript(fmt.Sprintf("p/a%02d.jsonl", i), line1)
	}
	f.port.FailAll = fmt.Errorf("creds: vend failed: %w", formats.ErrCredentialsRefused)

	rep, err := engine.Run(context.Background(), f.store, f.opts())

	require.ErrorIsf(t, err, formats.ErrCredentialsRefused, "want a refusal error from the run, got %v", err)
	assert.Truef(t, rep.Failed <= 1, "%d files failed; the run should stop at the first refusal", rep.Failed)
	assert.Equalf(t, 0, rep.Shipped, "%d files shipped despite refused credentials", rep.Shipped)
}

// An ordinary upload error is NOT fatal: those are per-object and the run continues.
func TestAnOrdinaryUploadErrorDoesNotStopTheRun(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 5; i++ {
		f.writeTranscript(fmt.Sprintf("p/b%02d.jsonl", i), line1)
	}
	f.port.FailAll = errors.New("connection reset by peer")

	rep, err := engine.Run(context.Background(), f.store, f.opts())
	require.NoErrorf(t, err, "an ordinary upload failure ended the run: %v", err)
	assert.Equalf(t, 5, rep.Failed, "want all 5 attempted and failed, got %+v", rep)
}
