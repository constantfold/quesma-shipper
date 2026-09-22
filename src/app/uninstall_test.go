package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUninstallKeepsStateUnlessPurged(t *testing.T) {
	for _, purge := range []bool{false, true} {
		stateDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(stateDir, "enrollment.json"), []byte("state"), 0o600))
		var steps []UninstallStep
		require.NoError(t, uninstallState(stateDir, purge, func(step UninstallStep) { steps = append(steps, step) }))
		_, err := os.Stat(stateDir)
		assert.Truef(t, !purge || os.IsNotExist(err), "purge left state behind: %v", err)
		assert.Truef(t, purge || err == nil, "ordinary uninstall removed state: %v", err)
		assert.Truef(t, len(steps) == 1 && (!purge || steps[0].Done != "") && (purge || steps[0].Skip != ""), "purge=%v reported %#v", purge, steps)
	}
}
