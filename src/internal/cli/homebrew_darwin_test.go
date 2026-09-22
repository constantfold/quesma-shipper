package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

type homebrewUpdateTransport struct{ calls int }

func (transport *homebrewUpdateTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("test update endpoint unavailable")
}

func TestHomebrewSelfUpdatesButBrewUninstalls(t *testing.T) {
	if os.Getenv("QUESMA_TEST_BREW_CHILD") == "1" {
		require.True(t, packaging.HomebrewManaged(), "did not recognize the cask executable")
		build := app.Build{Version: "1.0.0", Release: true}
		var out bytes.Buffer
		transport := &homebrewUpdateTransport{}
		previous := http.DefaultTransport
		http.DefaultTransport = transport
		defer func() { http.DefaultTransport = previous }()
		t.Setenv(app.NoSelfUpdateEnv, "1")
		t.Setenv(app.ReexecGuardEnv, "")
		maybeSelfUpdate(context.Background(), build, true, &out)
		require.Equal(t, 0, transport.calls, "self-update ignored the explicit disable switch")
		t.Setenv(app.NoSelfUpdateEnv, "")
		out.Reset()
		maybeSelfUpdate(context.Background(), build, true, &out)
		if transport.calls == 0 || !strings.Contains(out.String(), "test update endpoint unavailable") {
			t.Fatalf("automatic update did not reach TUF: %s", &out)
		}
		execute := func(args ...string) error {
			out.Reset()
			cmd := Root(build, &out, &out)
			cmd.SetArgs(args)
			return cmd.Execute()
		}
		transport.calls = 0
		if err := execute("update"); err == nil || transport.calls == 0 || !strings.Contains(err.Error(), "test update endpoint unavailable") {
			t.Fatalf("manual update did not reach TUF: %v", err)
		}
		_, paths, err := app.ResolveEffective()
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(paths.StateDir, 0o700))
		marker := filepath.Join(paths.StateDir, "preserve")
		require.NoError(t, os.WriteFile(marker, []byte("state"), 0o600))
		for _, args := range [][]string{{"uninstall"}, {"uninstall", "--purge"}} {
			purge := len(args) > 1
			if err := execute(args...); err == nil || !strings.Contains(err.Error(), "uninstall asks first") || !strings.Contains(out.String(), "Homebrew command") {
				t.Fatalf("uninstall confirmation: %v, %s", err, &out)
			}
			require.FileExists(t, marker, "state changed before confirmation")
			if err := execute(append(args, "--yes")...); err != nil || !strings.Contains(out.String(), packaging.BrewUninstall) {
				t.Fatalf("uninstall --yes: %v, %s", err, &out)
			}
			if _, err := os.Stat(marker); (!purge && err != nil) || (purge && !os.IsNotExist(err)) {
				t.Fatalf("state after purge=%v: %v", purge, err)
			}
		}
		return
	}

	root := t.TempDir()
	executable, err := os.Executable()
	require.NoError(t, err)
	raw, err := os.ReadFile(executable)
	require.NoError(t, err)
	installed := filepath.Join(root, "Caskroom", "quesma-shipper", "1.0.0", "quesma-shipper")
	require.NoError(t, os.MkdirAll(filepath.Dir(installed), 0o755))
	require.NoError(t, os.WriteFile(installed, raw, 0o755))
	link := filepath.Join(root, "shipper")
	require.NoError(t, os.Symlink(installed, link))
	cmd := exec.Command(link, "-test.run=^TestHomebrewSelfUpdatesButBrewUninstalls$")
	cmd.Env = append(os.Environ(), "QUESMA_TEST_BREW_CHILD=1", "HOME="+root, "XDG_STATE_HOME="+filepath.Join(root, "state"), "XDG_CONFIG_HOME="+filepath.Join(root, "config"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cask subprocess: %v\n%s", err, out)
	}
	require.FileExists(t, installed, "Brew payload was removed")
}
