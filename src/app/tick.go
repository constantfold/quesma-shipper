package app

import (
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// CatchUpDelay follows a truncated run: max_files_per_run keeps a run short rather than rationing
// throughput, and a short pause keeps every per-run property intact.
const CatchUpDelay = 15 * time.Second

// NextDelay catches up only after a clean, truncated run: re-ticking fast on a failure (a panic is an
// error too) makes a hot loop.
func NextDelay(rep formats.Report, err error, tick time.Duration) time.Duration {
	// Per-file failures return no error, so catch-up also requires something to have shipped.
	if err == nil && rep.Truncated && rep.Shipped > 0 {
		return CatchUpDelay
	}
	return tick
}
