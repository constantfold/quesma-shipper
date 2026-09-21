package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServiceInstallationBelongsToThePackager(t *testing.T) {
	for _, cmd := range serviceCmd().Commands() {
		require.NotEqual(t, "install", cmd.Name(), "service install is exposed through the CLI")
	}
}
