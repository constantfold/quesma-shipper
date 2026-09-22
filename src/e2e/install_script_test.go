// install.sh against a stub shipper that records its argv: the script's job is wiring, and the
// verbs it calls are tested on their own.
package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const stubShipper = `#!/bin/sh
echo "$@" >> "$SHIPPER_STUB_LOG"
[ "$1" = --version ] && echo "quesma-shipper 0.0.0-stub"
exit 0
`

func TestInstallScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is unix-only")
	}
	script, err := filepath.Abs(filepath.Join("..", "packaging", "linux", "install.sh"))
	require.NoError(t, err)

	for _, tc := range []struct {
		name        string
		enrolled    bool
		missingFrom bool // --from names a file that does not exist
		args        []string
		wantErr     bool
		wantOut     string
		wantCalls   []string
	}{
		{name: "PlacesALocalBinaryAndLogsIn", args: []string{"inv-1", "--server", "http://cp.example"},
			wantCalls: []string{"--version", "login --server http://cp.example inv-1", "postinstall"}},
		{name: "KeepsAnExistingLogin", enrolled: true, args: []string{"--no-service"}, wantOut: "already logged in", wantCalls: []string{"--version"}},
		{name: "DoesNotRequireEnrollment", args: []string{"--no-service"}, wantOut: "not enrolled", wantCalls: []string{"--version"}},
		{name: "RequiresServerBeforeChangingAnything", args: []string{"token", "--no-service"}, wantErr: true, wantOut: "pass --server URL"},
		{name: "ChecksLocalInputBeforeChangingAnything", missingFrom: true, args: []string{"token", "--no-service"}, wantErr: true, wantOut: "no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := stageBareWorld(t)
			bin := filepath.Join(w.Home, "bin")
			shipper, stubLog := filepath.Join(bin, "quesma-shipper"), filepath.Join(w.Home, "stub.log")
			if tc.enrolled {
				require.NoError(t, os.MkdirAll(statePath(w), 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(statePath(w), "enrollment.json"), []byte("{}"), 0o600))
			}
			from := shipper + ".missing"
			if !tc.missingFrom {
				from = filepath.Join(t.TempDir(), "shipper-local")
				require.NoError(t, os.WriteFile(from, []byte(stubShipper), 0o600))
			}

			cmd := exec.Command("sh", append([]string{script, "--bin-dir", bin, "--from", from}, tc.args...)...)
			cmd.Env = []string{
				"PATH=" + os.Getenv("PATH"),
				"HOME=" + w.Home,
				"XDG_STATE_HOME=" + w.State,
				"SHIPPER_STUB_LOG=" + stubLog,
			}
			raw, err := cmd.CombinedOutput()
			out := string(raw)
			require.Equalf(t, tc.wantErr, err != nil, "install.sh ended %v:\n%s", err, out)
			assert.Contains(t, out, tc.wantOut)

			var calls []string
			if log, err := os.ReadFile(stubLog); err == nil {
				calls = strings.Split(strings.TrimSpace(string(log)), "\n")
			}
			assert.Equal(t, tc.wantCalls, calls)

			if placed, err := os.ReadFile(shipper); tc.wantErr {
				assert.NoFileExists(t, shipper, "destination changed")
			} else {
				assert.Equalf(t, stubShipper, string(placed), "binary not placed: %v\n%s", err, out)
			}
		})
	}
}
