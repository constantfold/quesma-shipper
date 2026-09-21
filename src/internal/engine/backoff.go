package engine

import (
	"time"
)

// backoffCap bounds retry backoff. There is no max-retry: giving up is silent data loss.
const backoffCap = time.Hour

// backoffFor computes the next attempt delay: a minute, doubling, capped at an hour, with up to
// 12.5% of jitter subtracted so correlated failures do not wake together. Derived from attempt and
// spread rather than rand, so runs stay reproducible, and subtracted so the cap stays a ceiling.
func backoffFor(attempt int, spread uint64) time.Duration {
	d := min(time.Minute<<min(attempt, 8), backoffCap)
	// Up to an eighth off, so the spread is visible without meaningfully shortening the delay.
	jitter := time.Duration(spread%9) * d / 64
	return d - jitter
}
