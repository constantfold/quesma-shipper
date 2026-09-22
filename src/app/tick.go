package app

import (
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// CatchUpDelay replaces the tick interval after a truncated run, so a backlog converges at upload speed.
const CatchUpDelay = 15 * time.Second

// NextDelay re-ticks fast only after a clean truncated run that shipped; on failure that is a hot loop.
func NextDelay(rep formats.Report, err error, tick time.Duration) time.Duration {
	if err == nil && rep.Truncated && rep.Shipped > 0 {
		return CatchUpDelay
	}
	return tick
}
