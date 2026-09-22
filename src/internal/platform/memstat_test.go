package platform_test

import (
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// The default must actually reach the runtime: a limit computed, logged and never applied is a missing safeguard.
func TestTheDefaultLimitIsApplied(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "")
	previous := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(previous) })

	applied, fromEnv := platform.SetSoftLimit(platform.DefaultSoftLimit)
	require.True(t, !fromEnv, "reported GOMEMLIMIT with none set")
	assert.Equalf(t, int64(platform.DefaultSoftLimit), applied, "applied %d, want %d", applied, platform.DefaultSoftLimit)
	assert.Equal(t, int64(platform.DefaultSoftLimit), debug.SetMemoryLimit(-1))
}

// An operator who set GOMEMLIMIT has decided what this process may use; overriding them silently would be worse.
func TestGOMEMLIMITWins(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "700MiB")
	previous := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(previous) })

	const operatorChoice = 700 << 20
	debug.SetMemoryLimit(operatorChoice) // what the runtime does with the variable at startup

	applied, fromEnv := platform.SetSoftLimit(platform.DefaultSoftLimit)
	assert.True(t, fromEnv, "GOMEMLIMIT was set and the default was applied anyway")
	assert.Equalf(t, int64(operatorChoice), applied, "reported %d, want the operator's %d", applied, operatorChoice)
}

// The cap is process-wide, so a test that moves it puts it back, registered before the t.Setenv that follows.
func capFromEnv(t *testing.T, value string) {
	t.Helper()
	t.Cleanup(func() {
		require.NoError(t, platform.ApplyMaxInFlightBytesFromEnv())
	})
	t.Setenv(platform.EnvMaxInFlightBytes, value)
}

func TestTheInFlightCapTakesTheEnvironmentOverride(t *testing.T) {
	capFromEnv(t, "4194304")

	require.NoError(t, platform.ApplyMaxInFlightBytesFromEnv())
	assert.Equal(t, int64(4<<20), platform.MaxInFlightBytes())
}

// Unset is the production path; blank is what a cleared shell variable leaves behind and must read the same.
func TestTheInFlightCapDefaultsWithoutTheEnvironment(t *testing.T) {
	// Each case leaves the variable in a state that has to read as "no cap was asked for".
	for name, clearIt := range map[string]func(*testing.T){
		"unset": func(*testing.T) { os.Unsetenv(platform.EnvMaxInFlightBytes) },
		"blank": func(t *testing.T) { t.Setenv(platform.EnvMaxInFlightBytes, "   ") },
	} {
		t.Run(name, func(t *testing.T) {
			// Moved off the default first, so the call below reports a cap it restored rather than one it never touched.
			capFromEnv(t, "4194304")
			require.NoError(t, platform.ApplyMaxInFlightBytesFromEnv())

			clearIt(t)
			require.NoError(t, platform.ApplyMaxInFlightBytesFromEnv())
			assert.Equal(t, int64(platform.DefaultMaxInFlightBytes), platform.MaxInFlightBytes())
		})
	}
}

// A cap that cannot be honoured is refused: falling back would run at 512 MiB while the operator believed otherwise.
func TestAnUnusableInFlightCapIsRefused(t *testing.T) {
	for _, value := range []string{"banana", "0", "-1", "512MiB", "4.5"} {
		t.Run(value, func(t *testing.T) {
			before := platform.MaxInFlightBytes()
			capFromEnv(t, value)

			err := platform.ApplyMaxInFlightBytesFromEnv()
			require.Error(t, err)
			assert.Truef(t, strings.Contains(err.Error(), platform.EnvMaxInFlightBytes) && strings.Contains(err.Error(), value), "diagnostic %q names neither the variable nor the value", err)
			assert.Equal(t, platform.MaxInFlightBytes(), before)
		})
	}
}

func TestAReadingDescribesTheRun(t *testing.T) {
	before := platform.ReadMemStats()
	junk := make([]byte, 32<<20)
	for i := range junk {
		junk[i] = byte(i)
	}
	d := platform.Delta{Before: before, After: platform.ReadMemStats()}
	assert.Truef(t, d.Growth() > 0, "allocating 32 MB showed growth of %d", d.Growth())
	assert.NotEqual(t, "", d.String(), "empty summary")
	runtime.KeepAlive(junk)
}
