package controlplane_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	pathpkg "path"
	"strings"
	"testing"
	"time"

	protocol "github.com/QuesmaOrg/shipper-protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
)

// authFixture covers both versions of fixtures/*/auth/headers.json. Absent members stay zero:
// v1 has no signing prefix and v2 has no config exchange.
type authFixture struct {
	Comment          string         `json:"comment"`
	Organization     string         `json:"organization"`
	InstallID        string         `json:"install_id"`
	DeviceKeySeedHex string         `json:"device_key_seed_hex"`
	DevicePublicKey  string         `json:"device_public_key"`
	ServerTime       time.Time      `json:"server_time"`
	SigningPrefix    string         `json:"signing_prefix"`
	Config           authExchange   `json:"config"`
	Authorize        authExchange   `json:"authorize"`
	Rejected         []authExchange `json:"rejected"`
}

type authExchange struct {
	Name          string `json:"name"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Body          string `json:"body"`
	Authorization string `json:"authorization"`
}

func loadAuthFixture(t *testing.T, version string) (authFixture, ed25519.PrivateKey) {
	t.Helper()
	raw, err := fs.ReadFile(protocol.FS, pathpkg.Join("fixtures", version, "auth", "headers.json"))
	require.NoError(t, err)
	var fx authFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&fx))
	seed, err := hex.DecodeString(fx.DeviceKeySeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("device_key_seed_hex is not a %d-byte hex seed: %v", ed25519.SeedSize, err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	require.Equal(t, base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), fx.DevicePublicKey)
	return fx, key
}

// The golden authorization headers are internally consistent: each signature verifies over
// the exact body bytes against the fixture's public key.
func TestAuthFixtureGoldensVerify(t *testing.T) {
	fx, key := loadAuthFixture(t, "v1")
	sig := deviceSignature(t, fx.Config.Authorization, fx.Organization, fx.InstallID)
	assert.True(t, ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(fx.Config.Body), sig),
		"the v1 golden signature does not verify over its body")
}

// v2SigningPrefix is the domain-separating preamble from PROTOCOL.md, spelled out here so a
// silent change to either the fixture or the client fails rather than redefines it.
const v2SigningPrefix = "trajectory-shipper-upload-authorize-v2\nPOST\n/v2/uploads/authorize\n"

// v2SigningInput is the signed byte sequence for one method and path: the domain prefix built
// from those fixed protocol values, then the exact body bytes.
func v2SigningInput(method, path, body string) []byte {
	return []byte("trajectory-shipper-upload-authorize-v2\n" + method + "\n" + path + "\n" + body)
}

// v2Fresh mirrors the server's freshness window: 5 minutes old, 1 minute in the future.
func v2Fresh(issuedAt, serverTime time.Time) bool {
	return !issuedAt.Before(serverTime.Add(-5*time.Minute)) && !issuedAt.After(serverTime.Add(time.Minute))
}

func deviceSignature(t *testing.T, authorization, organization, installID string) []byte {
	t.Helper()
	want := "Shipper-Device org=" + organization + ", install=" + installID + ", sig="
	require.Truef(t, strings.HasPrefix(authorization, want), "authorization %q does not open with %q", authorization, want)
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, want))
	require.NoErrorf(t, err, "sig is not base64: %v", err)
	return sig
}

func authorizationOrganization(authorization string) string {
	const prefix = "Shipper-Device "
	if !strings.HasPrefix(authorization, prefix) {
		return ""
	}
	for _, field := range strings.Split(strings.TrimPrefix(authorization, prefix), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if ok && key == "org" {
			return value
		}
	}
	return ""
}

// The v2 golden is internally consistent, and every must-reject case fails for a reason the
// protocol gives: a signature that does not verify, or an issued_at outside the freshness window.
func TestAuthV2FixtureGoldensVerify(t *testing.T) {
	fx, key := loadAuthFixture(t, "v2")
	pub := key.Public().(ed25519.PublicKey)

	require.Equalf(t, v2SigningPrefix, fx.SigningPrefix, "fixture signing_prefix is %q, protocol says %q", fx.SigningPrefix, v2SigningPrefix)
	require.True(t, !fx.ServerTime.IsZero(), "v2 auth fixture carries no server_time, so freshness cannot be judged")

	golden := deviceSignature(t, fx.Authorize.Authorization, fx.Organization, fx.InstallID)
	assert.True(t, ed25519.Verify(pub, v2SigningInput(fx.Authorize.Method, fx.Authorize.Path, fx.Authorize.Body), golden), "the golden authorize signature does not verify over its domain-separated input")

	for _, rej := range fx.Rejected {
		t.Run(rej.Name, func(t *testing.T) {
			if authorizationOrganization(rej.Authorization) != fx.Organization {
				return
			}
			sig := deviceSignature(t, rej.Authorization, fx.Organization, fx.InstallID)
			if !ed25519.Verify(pub, v2SigningInput(rej.Method, rej.Path, rej.Body), sig) {
				return // refused on the signature, which is the point of the case
			}
			var carried struct {
				IssuedAt time.Time `json:"issued_at"`
			}
			require.NoError(t, json.Unmarshal([]byte(rej.Body), &carried))
			if v2Fresh(carried.IssuedAt, fx.ServerTime) {
				t.Errorf("this case verifies AND is fresh at %s, so nothing refuses it",
					fx.ServerTime.Format(time.RFC3339))
			}
		})
	}
}

// The v1 and v2 signing inputs differ over the same bytes: the fixture's "legacy body-only
// signature" is exactly what v1 signing produces, and it is not the v2 golden.
func TestV2SigningInputIsDomainSeparated(t *testing.T) {
	fx, key := loadAuthFixture(t, "v2")

	var legacy authExchange
	for _, rej := range fx.Rejected {
		if rej.Name == "legacy body-only signature" {
			legacy = rej
		}
	}
	require.NotEqual(t, "", legacy.Body, "v2 auth fixture has no 'legacy body-only signature' case to compare against")

	bodyOnly := base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(legacy.Body)))
	domainSeparated := base64.StdEncoding.EncodeToString(
		ed25519.Sign(key, v2SigningInput(fx.Authorize.Method, fx.Authorize.Path, fx.Authorize.Body)))

	assert.Equal(t, base64.StdEncoding.EncodeToString(deviceSignature(t, legacy.Authorization, fx.Organization, fx.InstallID)), bodyOnly)
	assert.Equal(t, base64.StdEncoding.EncodeToString(deviceSignature(t, fx.Authorize.Authorization, fx.Organization, fx.InstallID)), domainSeparated)
	assert.NotEqual(t, domainSeparated, bodyOnly, "v1 and v2 signatures agree over the same body: the domain separation is not there")
}

// The client reproduces the golden authorize exchange byte for byte: same body, same
// Authorization header over the domain-separated input.
func TestClientReproducesGoldenAuthorizeHeader(t *testing.T) {
	fx, key := loadAuthFixture(t, "v2")
	requestFixture, err := fs.ReadFile(protocol.FS, "fixtures/v2/uploads-authorize/request.json")
	require.NoError(t, err)
	responseFixture, err := fs.ReadFile(protocol.FS, "fixtures/v2/uploads-authorize/response.json")
	require.NoError(t, err)
	var req controlplane.AuthorizeRequest
	dec := json.NewDecoder(bytes.NewReader(requestFixture))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&req))

	server, got := controlPlane(t, http.StatusOK, string(responseFixture))

	client, err := controlplane.New(controlplane.Options{
		Endpoint:     server.URL,
		InstallID:    fx.InstallID,
		Organization: fx.Organization,
		DeviceKey:    key,
	})
	require.NoError(t, err)
	resp, err := client.AuthorizeUploads(context.Background(), req)
	require.NoErrorf(t, err, "authorize against the fixture response: %v", err)

	assert.Equalf(t, fx.Authorize.Path, got.path, "client posted to %s, protocol path is %s", got.path, fx.Authorize.Path)
	assert.Equalf(t, fx.Authorize.Body, string(got.body), "client posted body\n  %s\ngolden is\n  %s", string(got.body), fx.Authorize.Body)
	assert.Equalf(t, fx.Authorize.Authorization, got.authorization, "client built header\n  %s\ngolden is\n  %s", got.authorization, fx.Authorize.Authorization)

	var want controlplane.AuthorizeResponse
	require.NoError(t, json.Unmarshal(responseFixture, &want))
	assert.Equalf(t, resp, want, "decoded response %+v does not match the fixture %+v", resp, want)
}
