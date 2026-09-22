package app

import (
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// CatchUpDelay replaces the tick interval after a truncated run: max_files_per_run keeps one run
// short rather than rationing throughput.
const CatchUpDelay = 15 * time.Second

// NextDelay grants the catch-up delay only to a clean, truncated run that shipped something:
// re-ticking fast on failure, including per-file failures that return no error, is a hot loop.
func NextDelay(rep formats.Report, err error, tick time.Duration) time.Duration {
	if err == nil && rep.Truncated && rep.Shipped > 0 {
		return CatchUpDelay
	}
	return tick
}
