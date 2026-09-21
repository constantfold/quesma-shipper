// Self-update, the parts that answer without a network: the dev-build refusal and the config
// surface. The harness Build carries no release stamp, which is exactly what `update` must refuse:
// every release orders above a dev version, so a bare `update` would replace a developer's build.
package e2e

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateOnADevBuildRefusesAndNamesTheOverride(t *testing.T) {
	stageBareWorld(t)

	out, err := runExpectingFailure(t, "update")
	require.Errorf(t, err, "update on a dev build succeeded:\n%s", out)
	for _, want := range []string{"dev build", "make build"} {
		assert.Containsf(t, err.Error(), want, "the refusal does not mention %q: %v", want, err)
	}
}

func TestConfigShowReportsTheUpdateSwitch(t *testing.T) {
	stageBareWorld(t)

	out := run(t, "config")
	assert.Contains(t, out, "autoupdate.enabled")
}
