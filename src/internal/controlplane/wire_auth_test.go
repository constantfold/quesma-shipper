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

// authFixture covers both versions of fixtures/*/auth/headers.json; members a version lacks stay zero.
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
	require.NoError(t, err)
	require.Len(t, seed, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	require.Equal(t, base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), fx.DevicePublicKey)
	return fx, key
}

func deviceSignature(t *testing.T, authorization, organization, installID string) []byte {
	t.Helper()
	want := "Shipper-Device org=" + organization + ", install=" + installID + ", sig="
	require.True(t, strings.HasPrefix(authorization, want), "authorization %q does not open with %q", authorization, want)
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, want))
	require.NoError(t, err)
	return sig
}

// v2SigningInput spells out PROTOCOL.md's signed bytes, so a silent change to fixture or client fails.
func v2SigningInput(method, path, body string) []byte {
	return []byte("trajectory-shipper-upload-authorize-v2\n" + method + "\n" + path + "\n" + body)
}

// The v1 golden signature verifies over the exact body bytes against the fixture's public key.
func TestAuthFixtureGoldensVerify(t *testing.T) {
	fx, key := loadAuthFixture(t, "v1")
	sig := deviceSignature(t, fx.Config.Authorization, fx.Organization, fx.InstallID)
	assert.True(t, ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(fx.Config.Body), sig))
}

// The v2 golden verifies only with domain separation; each reject case is another org, a bad signature, or stale.
func TestAuthV2FixtureGoldensVerify(t *testing.T) {
	fx, key := loadAuthFixture(t, "v2")
	pub := key.Public().(ed25519.PublicKey)
	require.Equal(t, "trajectory-shipper-upload-authorize-v2\nPOST\n/v2/uploads/authorize\n", fx.SigningPrefix)
	require.False(t, fx.ServerTime.IsZero(), "v2 auth fixture carries no server_time, so freshness cannot be judged")

	golden := deviceSignature(t, fx.Authorize.Authorization, fx.Organization, fx.InstallID)
	assert.True(t, ed25519.Verify(pub, v2SigningInput(fx.Authorize.Method, fx.Authorize.Path, fx.Authorize.Body), golden))
	assert.False(t, ed25519.Verify(pub, []byte(fx.Authorize.Body), golden), "the golden verifies body-only: no domain separation")

	for _, rej := range fx.Rejected {
		t.Run(rej.Name, func(t *testing.T) {
			if !strings.Contains(rej.Authorization, "org="+fx.Organization+",") {
				return
			}
			sig := deviceSignature(t, rej.Authorization, fx.Organization, fx.InstallID)
			if !ed25519.Verify(pub, v2SigningInput(rej.Method, rej.Path, rej.Body), sig) {
				return
			}
			var carried struct {
				IssuedAt time.Time `json:"issued_at"`
			}
			require.NoError(t, json.Unmarshal([]byte(rej.Body), &carried))
			// The server's freshness window: 5 minutes old, 1 minute in the future.
			if !carried.IssuedAt.Before(fx.ServerTime.Add(-5*time.Minute)) && !carried.IssuedAt.After(fx.ServerTime.Add(time.Minute)) {
				t.Errorf("this case verifies AND is fresh at %s, so nothing refuses it", fx.ServerTime.Format(time.RFC3339))
			}
		})
	}
}

// The client reproduces the golden authorize exchange byte for byte: same path, body and Authorization header.
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
	c, err := controlplane.New(controlplane.Options{Endpoint: server.URL, InstallID: fx.InstallID, Organization: fx.Organization, DeviceKey: key})
	require.NoError(t, err)
	resp, err := c.AuthorizeUploads(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, fx.Authorize.Path, got.path)
	assert.Equal(t, fx.Authorize.Body, string(got.body))
	assert.Equal(t, fx.Authorize.Authorization, got.authorization)
	var want controlplane.AuthorizeResponse
	require.NoError(t, json.Unmarshal(responseFixture, &want))
	assert.Equal(t, want, resp)
}
