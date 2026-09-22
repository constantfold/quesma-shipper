//go:build linux

package linux

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSpec() Spec {
	return Spec{Executable: "/usr/local/bin/quesma-shipper", Args: []string{"run"},
		Home: "/home/jane", StateDir: "/home/jane/.local/state/trajectory-shipper",
		LogDir: "/home/jane/.local/state/trajectory-shipper/logs"}
}

// A done context fails exec.Cmd.Start before spawning, so this never reaches the real supervisor.
func TestRestartHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, RestartService(ctx), context.Canceled)
}

func TestUnitCarriesRestartEnvironmentAndLoginStart(t *testing.T) {
	got := renderUnit(testSpec())
	for _, want := range []string{"ExecStart=/usr/local/bin/quesma-shipper run", "Restart=always",
		"WantedBy=default.target", "Environment=HOME=/home/jane"} {
		assert.Containsf(t, got, want, "unit is missing %q", want)
	}
	assert.Falsef(t, strings.Contains(got, "User=") || strings.Contains(got, "[Timer]"), "user service contains system-level or timer configuration:\n%s", got)
}
