package engine_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// accountOpts points the run at a Codex account source over a fixture auth.json.
func accountOpts(t *testing.T, f *fixture) engine.Options {
	t.Helper()
	home := filepath.Join(f.home, ".codex")
	require.NoError(t, os.MkdirAll(home, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "auth.json"), []byte(`{"auth_mode":"apikey"}`), 0600))
	catalog, err := sources.Load()
	require.NoError(t, err)
	spec, _ := catalog.Source("codex-account")
	o := f.opts()
	o.Interval = 5 * time.Minute
	o.Env = sources.Env{Home: f.home, Lookup: func(string) (string, bool) { return "", false }}
	o.Sources = []sources.Resolved{{Source: spec, Root: home, Enabled: true, SpecFingerprint: sources.SpecFingerprint(spec)}}
	return o
}

func TestAccountHistoryUploadsFromMemoryAndRetriesCurrentUsage(t *testing.T) {
	f := newFixture(t)
	o := accountOpts(t, f)
	home := o.Sources[0].Root
	now := o.Now()
	o.Now = func() time.Time { return now }
	f.port.verdict = always(errors.New("offline"))
	f.runWith(o)
	if _, err := os.Stat(filepath.Join(f.stateDir, "snapshots")); !os.IsNotExist(err) {
		t.Fatal("account collection staged files")
	}
	require.NoError(t, os.WriteFile(filepath.Join(home, "auth.json"), []byte(`{"auth_mode":"fresh","tokens":{"id_token":"x.eyJlbWFpbCI6ImRldkBleGFtcGxlLm9yZyJ9.x"}}`), 0600))
	f.reopen()
	f.port.verdict = nil
	rep := f.runWith(o)
	require.Lenf(t, rep.Sources, 1, "expected one account source, got %d", len(rep.Sources))
	require.Truef(t, rep.Shipped == 1 && rep.Sources[0].Unreadable == 1 && rep.Sources[0].Reason != "", "retry current bucket must upload and report partial snapshot: %+v", rep)
	keys := f.port.keys()
	require.Lenf(t, keys, 1, "history keys %v", keys)
	for _, key := range keys {
		_, manifest, payload := f.openObject(t, key)
		require.Truef(t, !manifest.Derived && manifest.Enricher == nil && manifest.Gather == "account" && manifest.PayloadMTime != nil, "not a collector: %+v", manifest)
		lines := bytes.Split(payload, []byte("\n"))
		require.Truef(t, len(lines) == 3 && len(lines[2]) == 0, "expected two newline-terminated records: %s", payload)
		for _, line := range lines[:2] {
			require.Truef(t, json.Valid(line) && bytes.Contains(line, []byte(`"bucket_start":`)), "invalid account record: %s", line)
		}
		require.Truef(t, bytes.Contains(payload, []byte(`"auth_mode":"fresh"`)) && bytes.Contains(payload, []byte("dev@example.org")) && manifest.Redaction == nil, "fresh account payload altered: %s", payload)
	}
	f.reopen()
	now = now.Add(time.Minute)
	rep = f.runWith(o)
	require.Truef(t, rep.Shipped == 0 && rep.Unchanged == 1 && len(f.port.keys()) == 1, "same bucket should skip uploaded object: %+v", rep)
	now = now.Add(5 * time.Minute)
	rep = f.runWith(o)
	require.Equalf(t, 1, rep.Shipped, "new bucket %+v", rep)
	require.Len(t, f.port.keys(), 2, "remote history overwritten")
}

func TestSourceScrubSetting(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name    string
		setting *bool
		wantRaw bool
	}{{"default", nil, false}, {"enabled", &on, false}, {"disabled", &off, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			const raw = "{\"email\":\"dev@example.org\",\"access_token\":\"fixture-secret\"}\n"
			f.writeTranscript("projects/demo/session.jsonl", raw)
			o := f.opts()
			o.Sources[0].Scrub = tc.setting
			rep := f.runWith(o)
			require.Equalf(t, 1, rep.Shipped, "shipped: %+v", rep)
			for _, key := range f.port.keys() {
				_, m, payload := f.openObject(t, key)
				if tc.wantRaw {
					require.True(t, string(payload) == raw && m.Redaction == nil, "disabled scrub changed bytes or reported redaction")
				} else if bytes.Contains(payload, []byte("dev@example.org")) || bytes.Contains(payload, []byte("fixture-secret")) || m.Redaction == nil {
					t.Fatalf("scrubbing was not applied: %s", payload)
				}
			}
		})
	}
}
