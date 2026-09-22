//go:build darwin

package macos

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSpec() Spec {
	return Spec{Executable: "/usr/local/bin/quesma-shipper", Args: []string{"run"},
		Home: "/Users/jane", StateDir: "/Users/jane/.local/state/trajectory-shipper",
		LogDir: "/Users/jane/.local/state/trajectory-shipper/logs"}
}

// A done context fails exec.Cmd.Start before spawning, so these never reach the real supervisor.
func TestRestartHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, RestartService(ctx), context.Canceled)
}

func TestServiceStateHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, ServiceState(ctx).Loaded, "state with a canceled context must not read as loaded")
}

func TestPlistIsWellFormedAndKeepsTheAgentAlive(t *testing.T) {
	got := renderPlist(testSpec())
	require.NoError(t, xml.Unmarshal([]byte(got), new(any)))
	for _, want := range []string{"<key>RunAtLoad</key>\n\t<true/>", "<key>KeepAlive</key>\n\t<true/>",
		"<key>AssociatedBundleIdentifiers</key>\n\t<array>\n\t\t<string>" + bundleIdentifier + "</string>",
		"<string>/usr/local/bin/quesma-shipper</string>",
		"<key>HOME</key>", "XDG_STATE_HOME", "StandardOutPath", "StandardErrorPath"} {
		assert.Containsf(t, got, want, "plist is missing %q:\n%s", want, got)
	}

	spec := testSpec()
	spec.Home = "/Users/jane & co"
	spec.Executable = "/opt/<weird>/quesma-shipper"
	require.NoError(t, xml.Unmarshal([]byte(renderPlist(spec)), new(any)), "paths needing escapes broke the plist")
}

func TestLaunchAgentPathIsPerUser(t *testing.T) {
	got := launchdPath("/Users/jane")
	assert.Truef(t, strings.Contains(got, "Library/LaunchAgents") && !strings.Contains(got, "LaunchDaemons"), "unexpected launchd path: %q", got)
}
