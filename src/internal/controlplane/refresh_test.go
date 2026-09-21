package controlplane_test

import (
	"context"
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
	srv := p.start()

	// The standalone deployment: an endpoint exists in this test's world but nothing tells the
	// client to use it. Zero network calls is a property of the build, not of a firewall.
	remote := controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: nil,
		StateDir:   t.TempDir(),
		Now:        time.Now(),
	})
	assert.Equalf(t, controlplane.OriginNone, remote.Origin, "origin = %q, want none", remote.Origin)
	assert.Equalf(t, 0, p.configCalls, "an unenrolled install made %d config calls", p.configCalls)
	_ = srv
}

func TestRefreshCachesWhatItFetchedAndReusesItWhenTheServerIsGone(t *testing.T) {
	p := newPlane(t)
	p.config = "org: acme\nmax_files_per_run: 8\n"
	srv := p.start()
	dir := t.TempDir()

	e := p.enrolled(t, srv.URL, installID)
	now := time.Now()

	first := controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: e, StateDir: dir, Now: now,
	})
	require.Equalf(t, controlplane.OriginFetched, first.Origin, "origin = %q, want fetched", first.Origin)
	require.Truef(t, first.Doc != nil && first.Doc.MaxFilesPerRun != nil && *first.Doc.MaxFilesPerRun == 8, "served field did not arrive: %+v", first.Doc)
	assert.True(t, !first.Expired, "a config expiring in 24h was reported expired")

	// The ordinary case, a laptop off the VPN, and it must not stop collection: source stores are
	// reaped on their own schedules, so a skipped run loses data permanently.
	srv.Close()

	second := controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: e, StateDir: dir, Now: now,
	})
	require.Equalf(t, controlplane.OriginCached, second.Origin, "origin = %q, want cached", second.Origin)
	require.Truef(t, second.Doc != nil && second.Doc.MaxFilesPerRun != nil, "cached config did not come back: %+v", second.Doc)
	// The reason has to survive: a fallback that reported nothing would leave an operator
	// who pushed a config change unable to tell it had not taken effect.
	assert.Error(t, second.Err, "fell back to the cache without saying why")
	assert.True(t, !second.Expired, "a cached config inside its expiry was reported expired")
}

func TestAnExpiredCachedConfigKeepsCollectingAndIsFlagged(t *testing.T) {
	p := newPlane(t)
	p.expiresAt = time.Now().Add(1 * time.Hour)
	srv := p.start()
	dir := t.TempDir()

	e := p.enrolled(t, srv.URL, installID)
	controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: e, StateDir: dir, Now: time.Now(),
	})
	srv.Close()

	// Well past expiry, with no reachable server.
	later := time.Now().Add(72 * time.Hour)
	remote := controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: e, StateDir: dir, Now: later,
	})
	require.True(t, remote.Doc != nil, "an expired config produced no document; collection would lose its scope")
	assert.True(t, remote.Expired, "collecting under an expired config was not flagged, so no manifest would carry config_expired")
}

// A cache damaged on disk degrades to local config rather than stopping the run: collection
// under compiled defaults and the user's file beats collecting nothing.
func TestRefreshDegradesWhenTheCacheNoLongerParses(t *testing.T) {
	p := newPlane(t)
	srv := p.start()
	dir := t.TempDir()

	e := p.enrolled(t, srv.URL, installID)
	controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: e, StateDir: dir, Now: time.Now(),
	})
	srv.Close()

	// The config travels base64 inside the JSON document; "org: acme" becomes YAML the
	// parser refuses once its opening bracket has no close.
	path := filepath.Join(dir, controlplane.CacheFile)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	const encoded = "b3JnOiBhY21lCg==" // "org: acme\n"
	require.Containsf(t, string(raw), encoded, "cache does not hold the config where this test expects it:\n%s", raw)
	edited := strings.Replace(string(raw), encoded, "b3JnOiBbYWNtZQo=", 1) // "org: [acme\n"
	require.NoError(t, os.WriteFile(path, []byte(edited), 0o600))

	remote := controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: e, StateDir: dir, Now: time.Now(),
	})
	assert.Truef(t, remote.Origin == controlplane.OriginNone && remote.Doc == nil, "origin = %q with doc %+v, want no remote layer", remote.Origin, remote.Doc)
	assert.Truef(t, remote.Err != nil && strings.Contains(remote.Err.Error(), controlplane.CacheFile), "the unusable cache was not named: %v", remote.Err)
}

func TestOfflineRefreshResolvesFromTheCacheWithoutCalling(t *testing.T) {
	p := newPlane(t)
	srv := p.start()
	dir := t.TempDir()

	e := p.enrolled(t, srv.URL, installID)
	controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: e, StateDir: dir, Now: time.Now(),
	})
	calls := p.configCalls

	// What `config show` and `doctor` do. A read-only verb that fetched would change the
	// config it was asked to explain.
	remote := controlplane.Refresh(context.Background(), controlplane.RefreshOptions{
		Enrollment: e, StateDir: dir, Now: time.Now(), Offline: true,
	})
	assert.Equalf(t, controlplane.OriginCached, remote.Origin, "origin = %q, want cached", remote.Origin)
	assert.Equal(t, p.configCalls, calls)
}
