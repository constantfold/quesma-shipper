package config

import (
	"fmt"
	"strings"
	"time"
)

const (
	DefaultTick = 15 * time.Minute // the design's loss-window bound
	MinTick     = time.Minute      // a poll loop at seconds is a hot loop
)

// TickInterval turns `mode.schedule` into the tick interval; a bad value is refused with a warning and the default, never approximated.
func TickInterval(schedule string) (time.Duration, string) {
	s := strings.TrimSpace(schedule)
	if s == "" {
		return DefaultTick, ""
	}
	d, err := time.ParseDuration(s)
	var problem string
	switch {
	case err != nil:
		problem = `not a duration like "5m"`
	case d <= 0:
		problem = "a tick interval must be positive"
	case d < MinTick:
		return MinTick, fmt.Sprintf("mode.schedule %q is under the %s floor — ticking every %s", schedule, MinTick, MinTick)
	default:
		return d, ""
	}
	return DefaultTick, fmt.Sprintf("mode.schedule %q: %s — ticking every %s instead", schedule, problem, DefaultTick)
}
