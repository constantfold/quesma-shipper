package controlplane_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// Enrollment is unsigned; the subsequent config request identifies this install, and both carry client facts.
func TestClientRequestContract(t *testing.T) {
	p := newPlane(t)
	srv := p.start()
	c, err := controlplane.New(controlplane.Options{Endpoint: srv.URL})
	require.NoError(t, err)
	resp, err := c.Enroll(context.Background(), controlplane.EnrollRequest{
		InstallID: installID, DevicePublicKey: "device-pub", AgeRecipient: "age1recipient",
	})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.Organization)

	req := controlplane.ConfigRequest{AgentVersion: "0.1.0", ConfigVersions: []int{1}}
	_, err = p.client(t, srv.URL, installID).FetchConfig(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(p.lastAuth, "Shipper-Device org=acme, install="+installID), p.lastAuth)
	assert.Equal(t, req, p.lastReq)

	for _, path := range []string{"/v1/enroll", "/v1/config"} {
		for header, want := range map[string]string{
			controlplane.VersionHeader: platform.Current().String(),
			controlplane.OSHeader:      platform.OSVersion(),
			controlplane.BootHeader:    platform.BootTime(),
		} {
			assert.Equal(t, want, p.headersByPath[path].Get(header), "%s %s", path, header)
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
			p := newPlane(t)
			p.config, p.configStatus = tc.config, tc.status
			srv := p.start()
			_, err := p.client(t, srv.URL, installID).FetchConfig(context.Background(),
				controlplane.ConfigRequest{AgentVersion: "0.1.0"})
			require.Error(t, err)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
				assert.Contains(t, err.Error(), tc.detail)
			}
		})
	}
}

func TestEnrollmentRecordRoundTripsAndRefusesLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	dir := t.TempDir()
	p := newPlane(t)
	rec := p.enrolled(t, "https://plane.example", installID)
	require.NoError(t, rec.Save(dir))

	got, err := controlplane.LoadEnrollment(dir)
	require.NoError(t, err)
	assert.Truef(t, got.Organization == rec.Organization && got.DeviceKey == rec.DeviceKey, "record did not round-trip: %+v", got)
	if _, err := got.PrivateKey(); err != nil {
		t.Errorf("device key did not decode: %v", err)
	}

	// It holds a private signing key: a group-readable one is a finding, and the operator has to
	// know it was exposed rather than have it repaired silently.
	require.NoError(t, os.Chmod(filepath.Join(dir, controlplane.EnrollmentFile), 0o644))
	if _, err := controlplane.LoadEnrollment(dir); err == nil {
		t.Fatal("loaded an enrollment record readable by everyone")
	}
}

func TestMissingEnrollmentIsNotAnError(t *testing.T) {
	// Standalone is a supported deployment, not a degraded one: LoadEnrollment must report
	// plain os.ErrNotExist so callers can tell "no backend" from "broken backend".
	_, err := controlplane.LoadEnrollment(t.TempDir())
	require.ErrorIsf(t, err, os.ErrNotExist, "want os.ErrNotExist, got %v", err)
}

func TestEnrollmentSchemaMismatchIsRefused(t *testing.T) {
	dir := t.TempDir()
	body := fmt.Sprintf(`{"enrollment_schema":99,"install_id":%q,"organization":"acme",`+
		`"endpoint":"https://x","device_key":"","enrolled_at":"now"}`, installID)
	require.NoError(t, os.WriteFile(filepath.Join(dir, controlplane.EnrollmentFile), []byte(body), 0o600))
	if _, err := controlplane.LoadEnrollment(dir); err == nil {
		t.Fatal("accepted a record written by a version this client does not speak")
	}
}

// Every historical schema is a frozen fixture in testdata/ that must load through the migration
// ladder: a fleet on auto-update meets old records routinely, never by hand-editing JSON.
func TestHistoricalEnrollmentSchemasMigrateOnLoad(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("testdata", "enrollment-schema-*.json"))
	require.Truef(t, err == nil && len(fixtures) != 0, "no enrollment fixtures found: %v", err)
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			dir := t.TempDir()
			raw, err := os.ReadFile(fixture)
			require.NoError(t, err)
			path := filepath.Join(dir, controlplane.EnrollmentFile)
			require.NoError(t, os.WriteFile(path, raw, 0o600))

			e, err := controlplane.LoadEnrollment(dir)
			require.NoErrorf(t, err, "a known historical schema was refused: %v", err)
			// The identity material must survive verbatim: a migration that loses the
			// device key silently re-keys the install.
			assert.Truef(t, e.InstallID == "0f5a6b3c-1d2e-4f60-8a9b-1c2d3e4f5061" && e.Organization == "acme" && e.Endpoint == "https://cp.example.com" && e.EnrolledAt != "", "migrated record lost fields: %+v", e)
			if _, err := e.PrivateKey(); err != nil {
				t.Errorf("device key did not survive migration: %v", err)
			}

			// The upgrade is persisted once, at the current schema, still private.
			persisted, err := os.ReadFile(path)
			require.NoError(t, err)
			var onDisk map[string]any
			require.NoError(t, json.Unmarshal(persisted, &onDisk))
			if _, stale := onDisk["sink"]; stale {
				t.Error("persisted record still carries the schema-1 sink grant")
			}
			if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
				t.Errorf("persisted record is not private: %v %v", info.Mode(), err)
			}
			again, err := controlplane.LoadEnrollment(dir)
			require.NoErrorf(t, err, "the persisted migration does not load back: %v", err)
			assert.Truef(t, *again == *e, "second load differs from first: %+v vs %+v", again, e)
		})
	}
}
