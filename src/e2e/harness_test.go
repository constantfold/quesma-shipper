package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/cli"
)

// Fixed, because object keys derive from these: a minted-per-run unit would give a different key
// for the same file every time. The published key protects nothing and must never be used for real.
const (
	testInstallID   = "00000000-0000-4000-8000-000000000001"
	testAgeIdentity = "AGE-SECRET-KEY-1JF0Y36Z2RMJNJNN2AYUUF6HMHZVK3FCGK4GUADGRF9M3R57S2UCSDMJWD7"
	testNameKey     = "0101010101010101010101010101010101010101010101010101010101010101"
)

// A manifest carries payload_mtime and a checkout stamps whatever time it happened at, so every
// staged file gets this instead.
var fixtureMTime = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

const heartbeatKey = "state/heartbeat.json.age"

// world is one synthetic machine: a HOME the catalog finds sources under, the client's config and
// state, the plane that authorizes its uploads and the store they land in.
type world struct {
	Home     string
	Config   string // XDG_CONFIG_HOME
	State    string // XDG_STATE_HOME
	Identity *age.X25519Identity
	KeyRoot  string

	plane *fakePlane
	store *fakeStore
}

// stageWorld points the client at the machine through the environment, not flags, because the
// catalog resolves its roots through HOME. It is the enrolled shape, the only one that can upload.
func stageWorld(t *testing.T, opts ...func(*world)) *world {
	t.Helper()
	w := stageBareWorld(t)
	seedIdentity(t, w)

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	w.store = startFakeStore(t)
	w.plane = startFakePlane(t, w.store, pub)
	seedEnrollment(t, w, w.plane.server.URL, priv)

	writeConfig(t, w, "")
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Directories and environment only: no identity, no enrollment, no config. The world `enroll`
// meets, and with no enrollment record there is no route to any destination at all.
func stageBareWorld(t *testing.T) *world {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	w := &world{
		Home:    filepath.Join(root, "home"),
		Config:  filepath.Join(root, "config"),
		State:   filepath.Join(root, "state"),
		KeyRoot: "v1/organization=default/install=" + testInstallID,
	}
	for _, dir := range []string{w.Home, w.Config, w.State} {
		require.NoError(t, os.MkdirAll(dir, 0o700))
	}

	t.Setenv("HOME", w.Home)
	t.Setenv("USERPROFILE", w.Home)
	t.Setenv("APPDATA", filepath.Join(w.Home, "AppData", "Roaming"))
	t.Setenv("XDG_CONFIG_HOME", w.Config)
	t.Setenv("XDG_STATE_HOME", w.State)
	return w
}

func seedIdentity(t *testing.T, w *world) {
	t.Helper()
	id, err := age.ParseX25519Identity(testAgeIdentity)
	require.NoErrorf(t, err, "the test identity does not parse: %v", err)
	w.Identity = id

	dir := filepath.Join(w.State, "trajectory-shipper")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	unit := map[string]any{
		"identity_schema": 1,
		"install_id":      testInstallID,
		"age_identity":    testAgeIdentity,
		"age_recipient":   id.Recipient().String(),
		"name_key":        testNameKey,
		"created_at":      fixtureMTime.Format(time.RFC3339),
	}
	raw, err := json.Marshal(unit)
	require.NoError(t, err)
	// 0600: Load refuses a unit any wider, and that refusal is exercised here on purpose.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "identity.json"), raw, 0o600))
}

// 0600, because LoadEnrollment refuses anything wider and the file holds a private signing key.
func seedEnrollment(t *testing.T, w *world, endpoint string, deviceKey ed25519.PrivateKey) {
	t.Helper()
	record := map[string]any{
		"enrollment_schema": 2,
		"install_id":        testInstallID,
		"organization":      "default",
		"endpoint":          endpoint,
		"device_key":        base64.StdEncoding.EncodeToString(deviceKey),
		"enrolled_at":       fixtureMTime.Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(w.State, "trajectory-shipper", "enrollment.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

// writeConfig writes the client's own config; extra is appended verbatim, which is how a test says
// "and this source is disabled" without a second helper.
func writeConfig(t *testing.T, w *world, extra string) {
	t.Helper()
	require.True(t, w.store != nil, "writeConfig needs a staged object store; this world has none")
	dir := filepath.Join(w.Config, "trajectory-shipper")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	body := "config_version: 1\n" +
		// Deliberately a block an older build wrote: it selects nothing now, and every verb has to
		// keep working over it rather than failing to parse after an update.
		"send:\n  sink: file\n  path: /var/tmp/trajectory-archive\n" +
		// Pinned because the store speaks loopback HTTP, which only a configured entry may admit.
		"upload_targets:\n" +
		"  - origin: " + w.store.server.URL + "\n" +
		"    addressing: path-style\n" +
		"    path_prefix: /" + vendBucket + "\n" +
		"    allow_loopback_http: true\n" +
		// The 64-file default would truncate a grown fixture, and read as a collection bug.
		"max_files_per_run: 10000\n" +
		extra
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600))
}

// The install that enrolled and never configured upload_targets, running unpinned: tickets decide
// the destination, https only.
func writeConfigWithoutUploadTargets(t *testing.T, w *world) {
	t.Helper()
	dir := filepath.Join(w.Config, "trajectory-shipper")
	body := "config_version: 1\nmax_files_per_run: 10000\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600))
}

// run executes one command through the real command tree and returns its output.
func run(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	root := cli.Root(app.Build{Version: "e2e"}, &out, &out)
	root.SetArgs(args)
	require.NoError(t, root.Execute())
	return out.String()
}

func runOneShot(t *testing.T, flags ...string) string {
	t.Helper()
	return run(t, append([]string{"run", "--once"}, flags...)...)
}

// runExpectingFailure is for the paths whose whole point is a non-zero exit.
func runExpectingFailure(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := cli.Root(app.Build{Version: "e2e"}, &out, &out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func runUntilCancelled(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	root := cli.Root(app.Build{Version: "e2e"}, &out, &out)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	return out.String(), err
}

func runOneShotExpectingFailure(t *testing.T, flags ...string) (string, error) {
	t.Helper()
	return runExpectingFailure(t, append([]string{"run", "--once"}, flags...)...)
}

// stageFile writes one file into the synthetic HOME and stamps the fixed mtime on it.
func stageFile(t *testing.T, w *world, rel, content string) string {
	t.Helper()
	full := filepath.Join(w.Home, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	touch(t, full)
	return full
}

func touch(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.Chtimes(path, fixtureMTime, fixtureMTime))
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, f.Close())
	// Later than the fixture's on purpose: keeping the old timestamp would test the content hash
	// alone, and the mtime pre-filter is part of what runs.
	later := fixtureMTime.Add(time.Hour)
	require.NoError(t, os.Chtimes(path, later, later))
}

// A new mtime on every staged file without changing a byte: the case that decides whether change
// detection is correct.
func touchEverything(t *testing.T, w *world) {
	t.Helper()
	later := fixtureMTime.Add(2 * time.Hour)
	err := filepath.Walk(w.Home, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		return os.Chtimes(p, later, later)
	})
	require.NoError(t, err)
}

// Must stay in step with cursorjoin.DBCandidates: if that moves, the Cursor fixtures stop being
const cursorStateDB = "Cursor/User/globalStorage/state.vscdb"

// found and TestCursorPairYieldsOneDerivedObject fails rather than passing on the raw path.
func cursorStatePath() string {
	if runtime.GOOS == "darwin" {
		return "Library/Application Support/" + cursorStateDB
	}
	if runtime.GOOS == "windows" {
		return "AppData/Roaming/" + cursorStateDB
	}
	return ".config/" + cursorStateDB
}

func ensureDir(path string) error { return os.MkdirAll(path, 0o700) }
