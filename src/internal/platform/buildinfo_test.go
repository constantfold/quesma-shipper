package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One spelling everywhere: a version written one way in an object and another in a trace cannot be joined.
func TestTheVersionStringIsOneSpelling(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   Info
		want string
	}{
		{"a tagged build", Info{Version: "v0.4.1"}, "v0.4.1"},
		{"a tagged build from a modified tree", Info{Version: "v0.4.1", Modified: true}, "v0.4.1+dirty"},
		{"never doubled", Info{Version: "v0.4.1+dirty", Modified: true}, "v0.4.1+dirty"},
		{"an untagged build", Info{Version: "0.0.0-031a7faa8c16"}, "0.0.0-031a7faa8c16"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.in.String(), tc.want)
		})
	}
}

// A modified tree must be visible: an object shipped by one has code the sha alone cannot recover.
func TestAModifiedTreeIsVisibleInTheVersion(t *testing.T) {
	clean := Info{Version: "v1.0.0", Revision: "abc123"}.String()
	dirty := Info{Version: "v1.0.0", Revision: "abc123", Modified: true}.String()
	require.NotEqualf(t, dirty, clean, "a modified build is indistinguishable from a clean one: both %q", clean)
	assert.Containsf(t, dirty, "dirty", "the modified build reads %q, which does not say so", dirty)
}

// A release stamp is believed only when the toolchain corroborates it; a stamp that could lie would ship wrong provenance.
func TestAReleaseStampMustBeCorroborated(t *testing.T) {
	rev := "031a7faa8c1652f68ec214225df6657989113a1a"
	dev := Info{Version: "0.0.0-031a7faa8c16", Revision: rev}

	for _, tc := range []struct {
		name        string
		in          Info
		stamp       string
		wantVersion string
		wantRelease bool
	}{
		{"no stamp leaves a dev build alone", dev, "", "0.0.0-031a7faa8c16", false},
		{"a corroborated stamp is honored", dev, "0.0.1-123.031a7faa8c16", "0.0.1-123.031a7faa8c16", true},
		{"a stamp naming another commit is discarded", dev, "0.0.1-123.def456def456", "0.0.0-031a7faa8c16", false},
		{"a modified tree discards the stamp",
			Info{Version: "0.0.0-031a7faa8c16+dirty", Revision: rev, Modified: true},
			"0.0.1-123.031a7faa8c16", "0.0.0-031a7faa8c16+dirty", false},
		{"no revision to check against discards the stamp",
			Info{Version: "unknown"}, "0.0.1-123.031a7faa8c16", "unknown", false},
		{"a stamp with no hash part is discarded", dev, "0.0.1-nonsense", "0.0.0-031a7faa8c16", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := applyStamp(tc.in, tc.stamp)
			assert.Equalf(t, tc.wantVersion, got.String(), "String() = %q, want %q", got.String(), tc.wantVersion)
			assert.Equalf(t, tc.wantRelease, got.Release, "Release = %v, want %v", got.Release, tc.wantRelease)
		})
	}
}

// The stamp must not erase revision, commit time and platform: they are what corroborated it.
func TestAnHonoredStampKeepsTheToolchainRecord(t *testing.T) {
	in := Info{Version: "0.0.0-031a7faa8c16", Revision: "031a7faa8c1652f68ec214225df6657989113a1a",
		Time: "2026-08-06T08:31:31Z", GoVersion: "go1.25.0", OS: "linux", Arch: "amd64"}
	got := applyStamp(in, "0.0.1-123.031a7faa8c16")
	assert.Truef(t, got.Revision == in.Revision && got.Time == in.Time && got.OS == in.OS && got.Arch == in.Arch, "stamp rewrote the toolchain record: %+v", got)
}

// "unknown" is an acceptable answer; an empty string would reach a manifest as an absent client version.
func TestCurrentAlwaysAnswers(t *testing.T) {
	got := Current()
	assert.NotEqual(t, "", got.String(), "empty version string")
	assert.Truef(t, got.GoVersion != "" && got.OS != "" && got.Arch != "", "incomplete: %+v", got)
	assert.Equal(t, got.String(), Current().String(), "two calls disagreed")
}
