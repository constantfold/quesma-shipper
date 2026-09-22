package controlplane_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
)

// Zero network calls without enrollment is a property of the build, not of a firewall.
func TestRefreshWithNoEnrollmentMakesNoNetworkCall(t *testing.T) {
	p, _ := newPlane(t)
	remote := controlplane.Refresh(context.Background(), controlplane.RefreshOptions{StateDir: t.TempDir(), Now: time.Now()})
	assert.Equal(t, controlplane.OriginNone, remote.Origin)
	assert.Zero(t, p.configCalls)
}

// Cached policy survives offline inspection, server loss and expiry without changing the document.
func TestRefreshCacheLifecycle(t *testing.T) {
	p, srv := newPlane(t)
	now := time.Now()
	p.config = "org: acme\nmax_files_per_run: 8\n"
	o := controlplane.RefreshOptions{Enrollment: enrolled(t, srv.URL), StateDir: t.TempDir(), Now: now}
	first := controlplane.Refresh(context.Background(), o)
	require.Equal(t, controlplane.OriginFetched, first.Origin)
	require.NotNil(t, first.Doc)
	assert.False(t, first.Expired)
	require.NotNil(t, first.Doc.MaxFilesPerRun)
	assert.Equal(t, 8, *first.Doc.MaxFilesPerRun)

	calls := p.configCalls
	o.Offline = true
	offline := controlplane.Refresh(context.Background(), o)
	assert.Equal(t, controlplane.OriginCached, offline.Origin)
	assert.Equal(t, calls, p.configCalls, "inspection must not fetch policy")
	assert.Equal(t, first.Doc, offline.Doc)

	srv.Close()
	o.Offline = false
	for _, expired := range []bool{false, true} {
		if expired {
			o.Now = now.Add(72 * time.Hour)
		}
		cached := controlplane.Refresh(context.Background(), o)
		require.Equal(t, controlplane.OriginCached, cached.Origin)
		assert.Equal(t, first.Doc, cached.Doc, "expiry must not discard collection scope")
		assert.Error(t, cached.Err, "fallback must explain why the fetch failed")
		assert.Equal(t, expired, cached.Expired)
	}

	// A corrupt cached document must fall back to local policy and name the damaged file.
	path := filepath.Join(o.StateDir, controlplane.CacheFile)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString([]byte(p.config))
	require.Contains(t, string(raw), encoded)
	edited := strings.Replace(string(raw), encoded, base64.StdEncoding.EncodeToString([]byte("org: [acme\n")), 1)
	require.NoError(t, os.WriteFile(path, []byte(edited), 0o600))
	broken := controlplane.Refresh(context.Background(), o)
	assert.Equal(t, controlplane.OriginNone, broken.Origin)
	assert.Nil(t, broken.Doc)
	require.ErrorContains(t, broken.Err, controlplane.CacheFile)
}
