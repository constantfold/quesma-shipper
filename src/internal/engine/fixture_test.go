package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/identity"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// The suite's fixture: a minted install, an audit log, a fake port and one Claude Code source under a temp home.
type fixture struct {
	t        *testing.T
	home     string
	stateDir string
	store    *engine.Store
	port     *fakePort
	unit     *identity.Unit
	plan     engine.Options // policy only; opts adds the ports
	log      *auditlog.Log
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	home := t.TempDir()
	stateDir := filepath.Join(home, "state")
	unit, err := identity.Mint(stateDir)
	require.NoError(t, err)
	log, err := auditlog.Open(stateDir)
	require.NoError(t, err)

	f := &fixture{t: t, home: home, stateDir: stateDir, port: newPort(), unit: unit, log: log}
	f.plan = engine.Options{
		Interval: config.DefaultTick, StateDir: stateDir, MaxFilesPerRun: 64, ConfigVersion: 1, Deny: sources.New(home),
		RulePacks:    []string{"gitleaks-core", "quesma-extra", "cloud-keys", "generic-entropy", "pii-core"},
		StructuralEx: map[string][]string{"claude-code": {"uuid", "parentUuid", "sessionId"}, "*": {"timestamp", "version"}},
		Sources: []sources.Resolved{{
			Source: sources.Source{ID: "claude-code-transcripts", Family: "claude-code", Gather: "file_glob", ArtifactClass: "trajectory",
				Include: []string{"projects/**/*.jsonl"}, Sniff: &sources.Sniff{Kind: "jsonl", MaxScanBytes: 65536}},
			Root: filepath.Join(home, ".claude"), Enabled: true, SpecFingerprint: strings.Repeat("a", 64),
		}},
	}
	f.reopen()
	return f
}

func (f *fixture) reopen() {
	f.t.Helper()
	if f.store != nil {
		f.store.Close()
	}
	s, err := engine.Open(f.stateDir, f.unit.InstallID.String())
	require.NoError(f.t, err)
	f.store = s
	f.t.Cleanup(func() { s.Close() })
}

func (f *fixture) opts() engine.Options {
	o := f.plan
	o.Identity, o.Upload, o.Log = f.unit, f.port, f.log
	o.Recipients = []age.Recipient{f.unit.Recipient()}
	o.Now, o.Client = engineFixedTime, transforms.Client{Version: "0.1.0-test"}
	return o
}

func (f *fixture) run(adjust ...func(*engine.Options)) engine.Report {
	f.t.Helper()
	rep, err := f.try(adjust...)
	require.NoErrorf(f.t, err, "run: %v", err)
	return rep
}

// try is run for a test that expects the run to fail.
func (f *fixture) try(adjust ...func(*engine.Options)) (engine.Report, error) {
	o := f.opts()
	for _, fn := range adjust {
		fn(&o)
	}
	return engine.Run(context.Background(), f.store, o)
}

func (f *fixture) runWith(o engine.Options) engine.Report {
	f.t.Helper()
	return f.run(func(opts *engine.Options) { *opts = o })
}

func dryRun(o *engine.Options) { o.DryRun = true }

func engineFixedTime() time.Time { return time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC) }

func (f *fixture) writeTranscript(rel, body string) string {
	f.t.Helper()
	path := filepath.Join(f.home, ".claude", "projects", rel)
	require.NoError(f.t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(f.t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func (f *fixture) writeTranscripts(pattern string, count int) {
	f.t.Helper()
	for i := range count {
		f.writeTranscript(fmt.Sprintf(pattern, i), line1)
	}
}

const line1 = `{"type":"user","uuid":"u1","sessionId":"s1","cwd":"/Users/jane/work/api","message":{"content":[{"type":"text","text":"hello"}]}}` + "\n"

const line2 = `{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","message":{"content":[{"type":"text","text":"world"}]}}` + "\n"

func (f *fixture) openObject(t *testing.T, key string) (*fakeObject, transforms.Manifest, []byte) {
	t.Helper()
	obj, ok := f.port.get(key)
	require.True(t, ok, "missing stored object %s", key)
	manifest, payload, err := transforms.Open(obj.Body, f.unit.Identity)
	require.NoError(t, err, "open stored object %s", key)
	return obj, manifest, payload
}

// countStateWrites reports how many distinct state documents were seen on disk while fn ran.
func (f *fixture) countStateWrites(fn func()) int {
	path := filepath.Join(f.stateDir, engine.FileName)
	seen := map[string]bool{}
	stop, done := make(chan struct{}), make(chan int)
	go func() {
		for {
			select {
			case <-stop:
				done <- len(seen)
				return
			default:
			}
			if b, err := os.ReadFile(path); err == nil {
				seen[string(b)] = true
			}
			time.Sleep(time.Millisecond)
		}
	}()
	fn()
	close(stop)
	return <-done
}

// snapshot hashes every file under root, keyed by relative path.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	require.NoError(t, filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(path)
		sum := sha256.Sum256(body)
		rel, _ := filepath.Rel(root, path)
		out[rel] = hex.EncodeToString(sum[:])
		return err
	}))
	return out
}
