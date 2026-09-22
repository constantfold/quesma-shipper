package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewer(t *testing.T) {
	const latest = "0.0.1-124.def456def456"

	for _, tc := range []struct {
		name    string
		latest  string
		current string
		want    bool
	}{
		{"older release", latest, "0.0.1-123.abcdef123456", true},
		{"same release", latest, latest, false},
		{"newer release", latest, "0.0.1-125.aaaaaaaaaaaa", false},
		{"numeric commit count", latest, "0.0.1-99.bbb222bbb222", true},
		{"development build", latest, "0.0.0-031a7faa8c16", true},
		{"unknown build", latest, "unknown", false},
		{"new release line", "0.0.2-1.abcdef123456", "0.0.1-283.ad5a94045497", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, newer(tc.latest, tc.current))
		})
	}
}
