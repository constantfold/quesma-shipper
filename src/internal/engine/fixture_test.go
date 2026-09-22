package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

type fixture struct {
	t        *testing.T
	home     string
	stateDir string
	store    *engine.Store
	port     *fakePort
	unit     *identity.Unit
	eff      *config.Effective
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
	f.eff = f.effective(nil)
	f.reopen()
	return f
}

// effective builds a resolved config over a Claude-Code-shaped store, skipping the file layers.
func (f *fixture) effective(extraSources []sources.Resolved) *config.Effective {
	root := filepath.Join(f.home, ".claude")
	src := sources.Resolved{
		Source: sources.Source{
			ID:            "claude-code-transcripts",
			Family:        "claude-code",
			Gather:        "file_glob",
			ArtifactClass: "trajectory",
			Include:       []string{"projects/**/*.jsonl"},
			Sniff:         &sources.Sniff{Kind: "jsonl", MaxScanBytes: 65536},
		},
		Root:            root,
		Enabled:         true,
		SpecFingerprint: strings.Repeat("a", 64),
	}
	return &config.Effective{
		ConfigVersion:  1,
		MaxFilesPerRun: 64,
		StateDir:       f.stateDir,
		RulePacks:      []string{"gitleaks-core", "quesma-extra", "cloud-keys", "generic-entropy", "pii-core"},
		StructuralEx: map[string][]string{
			"claude-code": {"uuid", "parentUuid", "sessionId"},
			"*":           {"timestamp", "version"},
		},
		Sources:    append([]sources.Resolved{src}, extraSources...),
		Deny:       sources.New(f.home),
		Provenance: map[string]config.Origin{},
	}
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
	return engine.Options{
		Plan:       planOf(f.eff),
		Identity:   f.unit,
		Upload:     f.port,
		Log:        f.log,
		Recipients: []age.Recipient{f.unit.Recipient()},
		Now:        engineFixedTime,
		Client:     transforms.Client{Version: "0.1.0-test"},
	}
}

// countStateWrites reports how many times the state document was replaced while fn ran.
func (f *fixture) countStateWrites(fn func()) int {
	f.t.Helper()
	path := filepath.Join(f.stateDir, "fingerprints.json")
	seen := map[string]bool{}
	stop := make(chan struct{})
	done := make(chan int)
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

// runWith is run() with the options adjusted, for the settings only a test sets.
func (f *fixture) runWith(adjust ...func(*engine.Options)) engine.Report {
	f.t.Helper()
	o := f.opts()
	for _, fn := range adjust {
		fn(&o)
	}
	rep, err := engine.Run(context.Background(), f.store, o)
	require.NoErrorf(f.t, err, "run: %v", err)
	return rep
}

// wipeState is state loss: the fingerprint file gone, everything on the store intact.
func (f *fixture) wipeState() {
	f.t.Helper()
	f.store.Close()
	require.NoError(f.t, os.Remove(filepath.Join(f.stateDir, engine.FileName)))
	f.reopen()
}

func (f *fixture) run() engine.Report {
	f.t.Helper()
	return f.runWith()
}

// runDry is preview: read, scrub and seal, but neither upload nor commit.
func (f *fixture) runDry() engine.Report {
	f.t.Helper()
	return f.runWith(func(o *engine.Options) { o.DryRun = true })
}

// runUnbounded is the drain: max_files_per_run does not apply.
func (f *fixture) runUnbounded() engine.Report {
	f.t.Helper()
	return f.runWith(func(o *engine.Options) { o.Unbounded = true })
}

// engineFixedTime is the fixture's clock, so pause timestamps are not wall-clock dependent.
func engineFixedTime() time.Time { return time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC) }

func (f *fixture) writeTranscript(rel, body string) string {
	f.t.Helper()
	path := filepath.Join(f.home, ".claude", "projects", rel)
	require.NoError(f.t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(f.t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func (f *fixture) appendTranscript(rel, body string) {
	f.t.Helper()
	path := filepath.Join(f.home, ".claude", "projects", rel)
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(f.t, err)
	defer fh.Close()
	if _, err := fh.WriteString(body); err != nil {
		f.t.Fatal(err)
	}
}

const line1 = `{"type":"user","uuid":"u1","sessionId":"s1","cwd":"/Users/jane/work/api","message":{"content":[{"type":"text","text":"hello"}]}}` + "\n"

const line2 = `{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","message":{"content":[{"type":"text","text":"world"}]}}` + "\n"

func statMTime(t *testing.T, path string) time.Time {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.ModTime()
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		rel, _ := filepath.Rel(root, path)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	require.NoError(t, err)
	return out
}

// planOf mirrors the app layer's planFor, over a realistic resolved configuration.
func planOf(eff *config.Effective) engine.Plan {
	interval, _ := config.TickInterval(eff.Schedule)
	return engine.Plan{
		Interval:       interval,
		OrganizationID: eff.OrganizationID,
		StateDir:       eff.StateDir,
		MaxFilesPerRun: eff.MaxFilesPerRun,
		Sources:        eff.Sources,
		RulePacks:      eff.RulePacks,
		StructuralEx:   eff.StructuralEx,
		Deny:           eff.Deny,
		ConfigVersion:  eff.ConfigVersion,
		ConfigExpired:  eff.ConfigExpired,
	}
}

func (f *fixture) openObject(t *testing.T, key string) (*fakeObject, transforms.Manifest, []byte) {
	t.Helper()
	obj, ok := f.port.get(key)
	require.True(t, ok, "missing stored object %s", key)
	manifest, payload, err := transforms.Open(obj.Body, f.unit.Identity)
	require.NoError(t, err, "open stored object %s", key)
	return obj, manifest, payload
}
