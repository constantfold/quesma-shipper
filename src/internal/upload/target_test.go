package upload

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUploadTargetAccepts(t *testing.T) {
	for _, tc := range []struct {
		spec TargetSpec
		want string
	}{
		{TargetSpec{Origin: "https://archive.example.invalid", Addressing: VirtualHosted}, "https://archive.example.invalid:443"},
		{TargetSpec{Origin: "https://archive.example.invalid:443", Addressing: VirtualHosted}, "https://archive.example.invalid:443"},
		{TargetSpec{Origin: "https://Archive.Example.Invalid", Addressing: VirtualHosted}, "https://archive.example.invalid:443"},
		{TargetSpec{Origin: "https://minio.example.invalid:9000", Addressing: PathStyle, PathPrefix: "/trajectories"}, "https://minio.example.invalid:9000"},
		{TargetSpec{Origin: "http://127.0.0.1:9000", Addressing: PathStyle, PathPrefix: "/bucket", AllowLoopbackHTTP: true}, "http://127.0.0.1:9000"},
	} {
		target, err := NewUploadTarget(tc.spec)
		require.NoError(t, err, tc.spec.Origin)
		assert.Equal(t, tc.want, target.Origin())
	}
}

func TestNewUploadTargetRejects(t *testing.T) {
	for name, spec := range map[string]TargetSpec{
		"plain http":                    {Origin: "http://archive.example.invalid", Addressing: VirtualHosted},
		"http on a non-loopback host":   {Origin: "http://archive.example.invalid", Addressing: VirtualHosted, AllowLoopbackHTTP: true},
		"wildcard host":                 {Origin: "https://*.example.invalid", Addressing: VirtualHosted},
		"user information":              {Origin: "https://user:pass@archive.example.invalid", Addressing: VirtualHosted},
		"fragment":                      {Origin: "https://archive.example.invalid#frag", Addressing: VirtualHosted},
		"query":                         {Origin: "https://archive.example.invalid?a=b", Addressing: VirtualHosted},
		"path":                          {Origin: "https://archive.example.invalid/bucket", Addressing: VirtualHosted},
		"opaque":                        {Origin: "https:archive.example.invalid", Addressing: VirtualHosted},
		"no host":                       {Origin: "https://", Addressing: VirtualHosted},
		"unknown scheme":                {Origin: "s3://archive.example.invalid", Addressing: VirtualHosted},
		"unknown addressing":            {Origin: "https://archive.example.invalid", Addressing: Addressing("dns-style")},
		"virtual-hosted with a prefix":  {Origin: "https://archive.example.invalid", Addressing: VirtualHosted, PathPrefix: "/bucket"},
		"path-style without a prefix":   {Origin: "https://minio.example.invalid", Addressing: PathStyle},
		"path-style root prefix":        {Origin: "https://minio.example.invalid", Addressing: PathStyle, PathPrefix: "/"},
		"path-style relative prefix":    {Origin: "https://minio.example.invalid", Addressing: PathStyle, PathPrefix: "bucket"},
		"path-style trailing slash":     {Origin: "https://minio.example.invalid", Addressing: PathStyle, PathPrefix: "/bucket/"},
		"path-style dot segment":        {Origin: "https://minio.example.invalid", Addressing: PathStyle, PathPrefix: "/bucket/../other"},
		"path-style escaped prefix":     {Origin: "https://minio.example.invalid", Addressing: PathStyle, PathPrefix: "/buck%65t"},
		"loopback flag on a real host":  {Origin: "https://localhost.example.invalid", Addressing: VirtualHosted, AllowLoopbackHTTP: true, PathPrefix: "/bucket"},
		"loopback name without a flag":  {Origin: "http://localhost:9000", Addressing: PathStyle, PathPrefix: "/bucket"},
		"loopback address without flag": {Origin: "http://[::1]:9000", Addressing: PathStyle, PathPrefix: "/bucket"},
	} {
		_, err := NewUploadTarget(spec)
		assert.Error(t, err, name)
	}
}

func TestUploadTargetListMatch(t *testing.T) {
	archive, err := NewUploadTarget(TargetSpec{Origin: "https://archive.example.invalid", Addressing: VirtualHosted})
	require.NoError(t, err)
	minio, err := NewUploadTarget(TargetSpec{Origin: "https://minio.example.invalid:9000", Addressing: PathStyle, PathPrefix: "/trajectories"})
	require.NoError(t, err)
	list := UploadTargetList{archive, minio}

	for url, want := range map[string]UploadTarget{
		"https://archive.example.invalid/v1/object.age?X-Amz-Signature=abc": archive,
		"https://archive.example.invalid:443/v1/object.age":                 archive,
		"https://ARCHIVE.example.invalid/v1/object.age":                     archive,
		"https://minio.example.invalid:9000/trajectories/v1/object.age":     minio,
	} {
		got, err := list.Match(url)
		require.NoError(t, err)
		assert.Equal(t, want, got, url)
	}
	for name, raw := range map[string]string{
		"other host":       "https://evil.example.invalid/v1/object.age",
		"other port":       "https://archive.example.invalid:8443/v1/object.age",
		"other scheme":     "http://archive.example.invalid/v1/object.age",
		"user information": "https://user@archive.example.invalid/v1/object.age",
		"fragment":         "https://archive.example.invalid/v1/object.age#frag",
		"opaque":           "https:archive.example.invalid",
		"no host":          "/v1/object.age",
		"unparseable":      "https://archive.example.invalid/v1/%zz.age",
	} {
		_, err := list.Match(raw)
		assert.Error(t, err, name)
	}
	_, err = list.Match("https://evil.example.invalid/v1/object.age")
	assert.ErrorIs(t, err, ErrNoTarget)
}

// An empty allowlist is unpinned: only a configured entry may admit anything weaker than https.
func TestEmptyAllowlistAdoptsTheTicketOrigin(t *testing.T) {
	target, err := UploadTargetList{}.Match("https://archive.example.invalid/v1/object.age")
	require.NoError(t, err)
	assert.Equal(t, UploadTarget{origin: "https://archive.example.invalid:443", addressing: addressingUnpinned}, target)
	for _, raw := range []string{"http://archive.example.invalid/v1/object.age", "http://127.0.0.1:9000/bucket/v1/object.age"} {
		_, err := UploadTargetList{}.Match(raw)
		assert.Error(t, err, raw)
	}
}

func assertNoURLLeak(t *testing.T, err error, rawURL string) {
	t.Helper()
	for _, secret := range []string{rawURL, "X-Amz-Signature", "deadbeef", "FIXTURE", "?"} {
		require.NotContains(t, err.Error(), secret, "error leaked a credential")
	}
}
