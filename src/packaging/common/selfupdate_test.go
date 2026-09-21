package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelfUpdateHopPersistsAndClears(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, WriteSelfUpdateHop(dir, "0.1.0-42.abcdef"))
	require.Equal(t, "0.1.0-42.abcdef", ReadSelfUpdateHop(dir))
	require.NoError(t, ClearSelfUpdateHop(dir))
	require.Equal(t, "", ReadSelfUpdateHop(dir))
}
