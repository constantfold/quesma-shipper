package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTickInterval(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
		warn bool
	}{
		{"15m", 15 * time.Minute, false}, // the documented default, explicitly
		{"90s", 90 * time.Second, false},
		{"1h", time.Hour, false},
		{"  10m  ", 10 * time.Minute, false}, // whitespace is not a meaning
		{"every day", DefaultTick, true},
		{"15", DefaultTick, true}, // bare number: ambiguous, and ParseDuration agrees
		{"-5m", DefaultTick, true},
		{"5s", MinTick, true}, // a poll loop at seconds is a hot loop
	} {
		got, warn := TickInterval(tc.in)
		assert.Equal(t, tc.want, got, tc.in)
		assert.Equal(t, tc.warn, warn != "", tc.in)
		if tc.warn {
			assert.Contains(t, warn, tc.in, "the warning must name the rejected value")
		}
	}
}
