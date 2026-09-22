package sources_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// An oversized file must be skipped AND counted, or it is excluded in silence while the source still reports collected.
func TestAnOversizedFileIsSkippedAndCounted(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "projects", "-Users-dev-work-demo")
	small := filepath.Join(dir, "11111111-1111-4111-8111-111111111111.jsonl")
	big := filepath.Join(dir, "22222222-2222-4222-8222-222222222222.jsonl")
	write(t, small, `{"type":"user"}`+"\n")
	// Sparse: the cap is checked against the stat, so a file this size must never be read.
	f, err := os.Create(big)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(300<<20))
	f.Close()

	src := source(filepath.Join(home, ".claude"), []string{"projects/**/*.jsonl"})
	src.MaxFileBytes = 256 << 20
	disc := discover(t, src, nil)

	require.Equal(t, 1, len(disc.Candidates))
	require.NotContains(t, disc.Candidates[0].RelPath, "22222222", "the oversized file became a candidate")
	require.Lenf(t, disc.Oversize, 1, "want one oversized file recorded, got %d", len(disc.Oversize))
	assert.Truef(t, disc.Oversize[0].Size > disc.Oversize[0].Limit, "recorded size %d is not over the limit %d", disc.Oversize[0].Size, disc.Oversize[0].Limit)
	// The source is still healthy: one bad file must not stop the other four hundred.
	assert.Equalf(t, sources.Collected, disc.Health, "health is %q, want collected — one oversized file is not a broken source", disc.Health)
}
