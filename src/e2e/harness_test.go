// Synthetic machines for the end-to-end tier: a HOME the catalog finds sources under, the client's
// config and state, and the fake plane and store its uploads go through. Commands run through the
// real command tree in process.
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

// Fixed, because object keys derive from these. Published: it protects nothing and must never be used for real.
const (
	testInstallID   = "00000000-0000-4000-8000-000000000001"
	testAgeIdentity = "AGE-SECRET-KEY-1JF0Y36Z2RMJNJNN2AYUUF6HMHZVK3FCGK4GUADGRF9M3R57S2UCSDMJWD7"
	testNameKey     = "0101010101010101010101010101010101010101010101010101010101010101"
)

// A manifest carries payload_mtime, so every staged file gets this rather than checkout time.
var fixtureMTime = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

const heartbeatKey = "state/heartbeat.json.age"

type world struct {
	Home     string
	Config   string // XDG_CONFIG_HOME
	State    string // XDG_STATE_HOME
	Identity *age.X25519Identity
	KeyRoot  string

	plane *fakePlane
	store *fakeStore
}

// The enrolled shape, the only one that can upload; the environment points the client at it via HOME.
func stageWorld(t *testing.T) *world {
	t.Helper()
	w := stageBareWorld(t)
	id, err := age.ParseX25519Identity(testAgeIdentity)
	require.NoError(t, err, "the test identity does not parse")
	w.Identity = id
	require.NoError(t, os.MkdirAll(statePath(w), 0o700))
	writeJSON(t, filepath.Join(statePath(w), "identity.json"), map[string]any{
		"identity_schema": 1,
		"install_id":      testInstallID,
		"age_identity":    testAgeIdentity,
		"age_recipient":   id.Recipient().String(),
		"name_key":        testNameKey,
		"created_at":      fixtureMTime.Format(time.RFC3339),
	})

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	w.store = startFakeStore(t)
	w.plane = startFakePlane(t, w.store, pub)
	writeJSON(t, filepath.Join(statePath(w), "enrollment.json"), map[string]any{
		"enrollment_schema": 2,
		"install_id":        testInstallID,
		"organization":      "default",
		"endpoint":          w.plane.server.URL,
		"device_key":        base64.StdEncoding.EncodeToString(priv),
		"enrolled_at":       fixtureMTime.Format(time.RFC3339),
	})

	writeConfig(t, w, "")
	return w
}

// 0600: the client refuses identity and enrollment files any wider.
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

// Directories and environment only: the world `enroll` meets, with no route to any destination.
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

func statePath(w *world) string {
	return filepath.Join(w.State, "trajectory-shipper")
}

func userConfigPath(w *world) string {
	return filepath.Join(w.Config, "trajectory-shipper", "config.yaml")
}

// The client's own config; extra is appended verbatim, such as a disabled source.
func writeConfig(t *testing.T, w *world, extra string) {
	t.Helper()
	body := "config_version: 1\n" +
		// A block an older build wrote: it selects nothing now, and every verb must still parse it.
		"send:\n  sink: file\n  path: /var/tmp/trajectory-archive\n" +
		// Listed because the store speaks loopback HTTP, which only a configured entry may admit.
		"upload_targets:\n" +
		"  - origin: " + w.store.server.URL + "\n" +
		"    addressing: path-style\n" +
		"    path_prefix: /" + vendBucket + "\n" +
		"    allow_loopback_http: true\n" +
		// The 64-file default would truncate a grown fixture, and read as a collection bug.
		"max_files_per_run: 10000\n" +
		extra
	require.NoError(t, os.MkdirAll(filepath.Dir(userConfigPath(w)), 0o700))
	require.NoError(t, os.WriteFile(userConfigPath(w), []byte(body), 0o600))
}

// One command through the real command tree, for the paths whose point is a non-zero exit.
func runExpectingFailure(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return execute(context.Background(), args)
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := execute(context.Background(), args)
	require.NoErrorf(t, err, "%v:\n%s", args, out)
	return out
}

func runOneShot(t *testing.T, flags ...string) string {
	t.Helper()
	return run(t, append([]string{"run", "--once"}, flags...)...)
}

// For a command that would otherwise wait forever.
func runUntilCancelled(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return execute(ctx, args)
}

func execute(ctx context.Context, args []string) (string, error) {
	var out bytes.Buffer
	root := cli.Root(app.Build{Version: "e2e"}, &out, &out)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	return out.String(), err
}

// One file in the synthetic HOME, stamped with the fixed mtime.
func stageFile(t *testing.T, w *world, rel, content string) string {
	t.Helper()
	full := filepath.Join(w.Home, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	require.NoError(t, os.Chtimes(full, fixtureMTime, fixtureMTime))
	return full
}

// A later mtime, so the mtime pre-filter runs rather than the content hash alone.
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString(line + "\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	later := fixtureMTime.Add(time.Hour)
	require.NoError(t, os.Chtimes(path, later, later))
}

// A new mtime on every staged file without changing a byte.
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

// Match cursorjoin.DBCandidates; TestCursorPairYieldsADerivedObjectAndKeepsTheRaw checks the derived path.
func cursorStatePath() string {
	const db = "Cursor/User/globalStorage/state.vscdb"
	switch runtime.GOOS {
	case "darwin":
		return "Library/Application Support/" + db
	case "windows":
		return "AppData/Roaming/" + db
	}
	return ".config/" + db
}
