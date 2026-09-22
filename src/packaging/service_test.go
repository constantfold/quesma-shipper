package packaging

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStateMarkersRoundTrip(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 7, 30, 10, 30, 0, 0, time.UTC)
	require.NoError(t, RecordRun(dir, at))
	require.True(t, lastRun(dir).Equal(at))
	require.NoError(t, os.WriteFile(filepath.Join(dir, runMarker), []byte("yesterday\n"), 0o644))
	require.True(t, lastRun(dir).IsZero(), "a corrupt marker was parsed as a real timestamp")

	require.NoError(t, WriteSelfUpdateHop(dir, "0.1.0-42.abcdef"))
	require.Equal(t, "0.1.0-42.abcdef", ReadSelfUpdateHop(dir))
	require.NoError(t, ClearSelfUpdateHop(dir))
	require.Equal(t, "", ReadSelfUpdateHop(dir))
	require.NoError(t, ClearSelfUpdateHop(dir))
}
