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

func TestRefreshWithNoEnrollmentMakesNoNetworkCall(t *testing.T) {
	p := newPlane(t)
	p.start()

	// The standalone deployment: an endpoint exists in this test's world but nothing tells the
	// client to use it. Zero network calls is a property of the build, not of a firewall.
	remote := controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: nil,
		StateDir:   t.TempDir(),
		Now:        time.Now(),
	})
	assert.Equalf(t, controlplane.OriginNone, remote.Origin, "origin = %q, want none", remote.Origin)
	assert.Equalf(t, 0, p.configCalls, "an unenrolled install made %d config calls", p.configCalls)
}

// Cached policy survives offline inspection, server loss and expiry without changing the document.
func TestRefreshCacheLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		ttl          time.Duration
		limit        int
	}{
		{"configured limit", "org: acme\nmax_files_per_run: 8\n", 24 * time.Hour, 8},
		{"short expiry", "org: acme\n", time.Hour, 0},
		{"defaults", "org: acme\n", 24 * time.Hour, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPlane(t)
			now := time.Now()
			p.config, p.expiresAt = tc.config, now.Add(tc.ttl)
			srv := p.start()
			o := controlplane.RefreshOptions{
				Enrollment: p.enrolled(t, srv.URL, installID), StateDir: t.TempDir(), Now: now,
			}
			first := controlplane.Refresh(context.Background(), o)
			require.Equal(t, controlplane.OriginFetched, first.Origin)
			require.NotNil(t, first.Doc)
			assert.False(t, first.Expired)
			if tc.limit != 0 {
				require.NotNil(t, first.Doc.MaxFilesPerRun)
				assert.Equal(t, tc.limit, *first.Doc.MaxFilesPerRun)
			}

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
			encoded := base64.StdEncoding.EncodeToString([]byte(tc.config))
			require.Contains(t, string(raw), encoded)
			edited := strings.Replace(string(raw), encoded, "b3JnOiBbYWNtZQo=", 1) // "org: [acme\n"
			require.NoError(t, os.WriteFile(path, []byte(edited), 0o600))
			o.Now = now
			broken := controlplane.Refresh(context.Background(), o)
			assert.Equal(t, controlplane.OriginNone, broken.Origin)
			assert.Nil(t, broken.Doc)
			require.Error(t, broken.Err)
			assert.Contains(t, broken.Err.Error(), controlplane.CacheFile)
		})
	}
}
