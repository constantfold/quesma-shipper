package engine_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// Unreadable files park across restarts, then recover even when their bytes revert to a committed hash.
func TestUnreadableFileBackoffAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		revert  bool
		shipped int
	}{
		{"first upload", false, 1},
		{"reverted to shipped bytes", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.writeTranscript("p/good.jsonl", line1)
			bad := f.writeTranscript("p/bad.jsonl", line1)
			if tc.revert {
				require.Equal(t, 2, f.run().Shipped)
				// A changed file bypasses the size-and-mtime pre-filter and reaches the failing read.
				f.writeTranscript("p/bad.jsonl", line1+line2)
			}
			require.NoError(t, os.Chmod(bad, 0o000))
			t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
			if _, err := os.ReadFile(bad); err == nil {
				t.Skip("this user can read a mode-000 file")
			}

			if tc.revert {
				f.reopen()
			}
			first := f.run()
			require.Truef(t, first.Parked == 1 && first.Failed == 0, "expected the unreadable file to park once, got %+v", first)
			if !tc.revert {
				f.reopen()
				second := f.run()
				assert.Equalf(t, 0, second.Parked, "the unreadable file was read again inside its backoff: %+v", second)
				assert.Equalf(t, 1, second.Skipped, "expected it to be skipped while parked, got %+v", second)
			}

			require.NoError(t, os.Chmod(bad, 0o600))
			if tc.revert {
				f.writeTranscript("p/bad.jsonl", line1)
			}
			f.reopen()
			rep := f.run(func(o *engine.Options) {
				later := o.Now().Add(2 * time.Hour)
				o.Now = func() time.Time { return later }
			})
			require.Equalf(t, tc.shipped, rep.Shipped, "unexpected uploads after the backoff: %+v", rep)
			if tc.revert {
				require.Equalf(t, 2, rep.Unchanged, "reverted bytes should be unchanged: %+v", rep)
			}

			doc, err := engine.Peek(f.stateDir)
			require.NoError(t, err)
			fp, ok := doc.Entries[engine.Key{SourceID: "claude-code-transcripts", NativePath: bad}]
			require.Truef(t, ok, "no entry for %s in %+v", bad, doc.Entries)
			assert.Truef(t, !fp.Parked && fp.LastError == "" && fp.Attempts == 0 && fp.BackoffUntil.IsZero(), "the park survived a clean read: %+v", fp)
		})
	}
}
