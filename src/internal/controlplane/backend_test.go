package controlplane_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// Enrollment is unsigned; the subsequent config request identifies this install, and both carry client facts.
func TestClientRequestContract(t *testing.T) {
	p, srv := newPlane(t)
	c, err := controlplane.New(controlplane.Options{Endpoint: srv.URL})
	require.NoError(t, err)
	resp, err := c.Enroll(context.Background(), controlplane.EnrollRequest{InstallID: installID, DevicePublicKey: "device-pub", AgeRecipient: "age1recipient"})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.Organization)
	assert.Empty(t, p.headers["/v1/enroll"].Get("Authorization"))

	req := controlplane.ConfigRequest{AgentVersion: "0.1.0", ConfigVersions: []int{1}}
	signed, _ := client(t, srv.URL)
	_, _, err = signed.FetchConfig(context.Background(), req)
	require.NoError(t, err)
	auth := p.headers["/v1/config"].Get("Authorization")
	assert.True(t, strings.HasPrefix(auth, "Shipper-Device org=acme, install="+installID), auth)
	assert.Equal(t, req, p.lastReq)

	for _, path := range []string{"/v1/enroll", "/v1/config"} {
		for header, want := range map[string]string{
			controlplane.VersionHeader: platform.Current().String(),
			controlplane.OSHeader:      platform.OSVersion(),
			controlplane.BootHeader:    platform.BootTime(),
		} {
			assert.Equal(t, want, p.headers[path].Get(header), "%s %s", path, header)
		}
	}
}

func TestFetchConfigRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, config, detail string
		status               int
		want                 error
	}{
		{"malformed document", "org: [acme\n", "", 0, nil},
		{"unsupported version", "org: acme\n", "Conflict", http.StatusConflict, controlplane.ErrUnsupportedVersion},
		{"revoked install", "org: acme\n", "403", http.StatusForbidden, formats.ErrCredentialsRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, srv := newPlane(t)
			p.config, p.configStatus = tc.config, tc.status
			c, _ := client(t, srv.URL)
			_, _, err := c.FetchConfig(context.Background(), controlplane.ConfigRequest{AgentVersion: "0.1.0"})
			require.Error(t, err)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
				assert.Contains(t, err.Error(), tc.detail)
			}
		})
	}
}

func TestEnrollmentRecord(t *testing.T) {
	// Standalone is a supported deployment: plain os.ErrNotExist tells "no backend" from "broken backend".
	_, err := controlplane.LoadEnrollment(t.TempDir())
	require.ErrorIs(t, err, os.ErrNotExist)

	dir := t.TempDir()
	rec := enrolled(t, "https://plane.example")
	require.NoError(t, rec.Save(dir))
	got, err := controlplane.LoadEnrollment(dir)
	require.NoError(t, err)
	rec.EnrollmentSchema = 2
	assert.Equal(t, rec, got)
	_, err = got.PrivateKey()
	assert.NoError(t, err)

	path := filepath.Join(dir, controlplane.EnrollmentFile)
	require.NoError(t, os.WriteFile(path, []byte(`{"enrollment_schema":99,"install_id":"x","device_key":""}`), 0o600))
	_, err = controlplane.LoadEnrollment(dir)
	require.Error(t, err, "accepted a record written by a version this client does not speak")

	if runtime.GOOS != "windows" {
		// It holds a private signing key: the operator has to know it was exposed rather than have it repaired silently.
		require.NoError(t, rec.Save(dir))
		require.NoError(t, os.Chmod(path, 0o644))
		_, err = controlplane.LoadEnrollment(dir)
		require.Error(t, err, "loaded an enrollment record readable by everyone")
	}
}

// Every historical schema is a frozen testdata/ fixture that must migrate: an auto-updating fleet meets them routinely.
func TestHistoricalEnrollmentSchemasMigrateOnLoad(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("testdata", "enrollment-schema-*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			dir := t.TempDir()
			raw, err := os.ReadFile(fixture)
			require.NoError(t, err)
			path := filepath.Join(dir, controlplane.EnrollmentFile)
			require.NoError(t, os.WriteFile(path, raw, 0o600))

			e, err := controlplane.LoadEnrollment(dir)
			require.NoError(t, err, "a known historical schema was refused")
			// A migration that loses the device key silently re-keys the install.
			assert.Equal(t, controlplane.Enrollment{EnrollmentSchema: 2, InstallID: installID, Organization: "acme",
				Endpoint: "https://cp.example.com", EnrolledAt: "2026-08-03T14:22:51Z",
				DeviceKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB5tVYuj+ZU+UB4sRLoqYunkB+FOuaVvtfg45ELrQSWZA=="}, *e)
			_, err = e.PrivateKey()
			assert.NoError(t, err, "device key did not survive migration")

			// The upgrade is persisted once, at the current schema, still private.
			persisted, err := os.ReadFile(path)
			require.NoError(t, err)
			var onDisk map[string]any
			require.NoError(t, json.Unmarshal(persisted, &onDisk))
			assert.NotContains(t, onDisk, "sink", "persisted record still carries the schema-1 sink grant")
			if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
				t.Errorf("persisted record is not private: %v %v", info.Mode(), err)
			}
			again, err := controlplane.LoadEnrollment(dir)
			require.NoError(t, err)
			assert.Equal(t, e, again)
		})
	}
}

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
