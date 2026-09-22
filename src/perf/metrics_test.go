//go:build perf

// What the store was asked for, read off toxiproxy's and MinIO's Prometheus pages.
package perf

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// What one run cost the store: bytes each way through the shaped proxy, and S3 calls served.
type storeCounters struct {
	up, down, requests int64
}

// The counters' growth across fn; nothing else may talk to the store meanwhile, adminS3 included.
func aroundStore(t *testing.T, fn func()) storeCounters {
	t.Helper()
	before, requestsBefore := settledStoreBytes(t), s3RequestCount(t)
	fn()
	after := settledStoreBytes(t)
	return storeCounters{
		up:       after.up - before.up,
		down:     after.down - before.down,
		requests: s3RequestCount(t) - requestsBefore,
	}
}

// toxiproxy counts each byte once received and once sent: up and down are received only, total is all four.
type storeBytes struct {
	up, down, total int64
}

// Only after the child exits: bytes are accounted when a link closes, and trail it, hence the settling poll.
func proxiedBytes(t *testing.T) int64 {
	t.Helper()
	return settledStoreBytes(t).total
}

func settledStoreBytes(t *testing.T) storeBytes {
	t.Helper()
	const (
		stableReads = 3
		interval    = 250 * time.Millisecond
		deadline    = 20 * time.Second
	)
	give := time.Now().Add(deadline)
	last, same := int64(-1), 0
	for {
		b := scrapeStoreBytes(t)
		if b.total == last {
			if same++; same >= stableReads-1 {
				return b
			}
		} else {
			last, same = b.total, 0
		}
		require.Falsef(t, time.Now().After(give), "toxiproxy's byte counters never settled: last read %d bytes", b.total)
		time.Sleep(interval)
	}
}

// The shaped proxy's label only, so the harness's own admin traffic is not charged to the shipper.
func scrapeStoreBytes(t *testing.T) storeBytes {
	t.Helper()
	var b storeBytes
	eachSample(t, metricsURL, scrapePage(t, metricsURL), func(name, labels string, value float64) {
		received := name == "toxiproxy_proxy_received_bytes_total"
		if !received && name != "toxiproxy_proxy_sent_bytes_total" ||
			!strings.Contains(labels, `proxy="`+storeProxyName+`"`) {
			return
		}
		b.total += int64(value)
		switch {
		case received && strings.Contains(labels, `direction="upstream"`):
			b.up += int64(value)
		case received && strings.Contains(labels, `direction="downstream"`):
			b.down += int64(value)
		}
	})
	return b
}

// Named here because a MinIO upgrade that renamed it would report every run as zero requests.
const s3RequestCountMetric = "minio_api_requests_total"

// A running total that counts the harness too, so nothing else may run between two readings.
func s3RequestCount(t *testing.T) int64 {
	t.Helper()
	page := scrapePage(t, minioMetricsURL)
	require.Truef(t, strings.Contains(page, s3RequestCountMetric), "no %s on %s: the pinned MinIO "+
		"renamed the counter and every request figure would read zero", s3RequestCountMetric, minioMetricsURL)
	var total int64
	eachSample(t, minioMetricsURL, page, func(name, labels string, value float64) {
		if name == s3RequestCountMetric && strings.Contains(labels, `type="s3"`) {
			total += int64(value)
		}
	})
	return total
}

// Whole, into memory: the text lets a caller catch a renamed metric instead of summing to zero.
func scrapePage(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	require.NoErrorf(t, err, "scrape %s", url)
	defer resp.Body.Close()
	require.Equalf(t, http.StatusOK, resp.StatusCode, "scrape %s", url)
	body, err := io.ReadAll(resp.Body)
	require.NoErrorf(t, err, "read %s", url)
	return string(body)
}

// Parsed by hand rather than with expfmt, which would be this module's only Prometheus dependency.
func eachSample(t *testing.T, url, page string, fn func(name, labels string, value float64)) {
	t.Helper()
	for line := range strings.SplitSeq(page, "\n") {
		name, labelled, ok := strings.Cut(line, "{")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		labels, value, ok := strings.Cut(labelled, "} ")
		require.Truef(t, ok, "unparseable sample line from %s: %q", url, line)
		f, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		require.NoErrorf(t, err, "unparseable sample value in %q", line)
		fn(name, labels, f)
	}
}
