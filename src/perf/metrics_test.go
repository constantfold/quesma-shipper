//go:build perf

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

// The difference between the counters read either side of fn, since they run for the life of the
// tier. Nothing else may talk to the store while fn runs: adminS3 lands in the same request count.
func aroundStore(t *testing.T, fn func()) storeCounters {
	t.Helper()
	upBefore, downBefore := proxiedBytesByDirection(t)
	requestsBefore := s3RequestCount(t)

	fn()

	up, down := proxiedBytesByDirection(t)
	return storeCounters{up: up - upBefore, down: down - downBefore, requests: s3RequestCount(t) - requestsBefore}
}

// One reading of the shaped proxy's four byte counters; toxiproxy counts each link's bytes twice,
// once received and once sent, so total is not up+down.
type storeBytes struct {
	receivedUp, receivedDown int64
	sentUp, sentDown         int64
}

func (b storeBytes) total() int64 {
	return b.receivedUp + b.receivedDown + b.sentUp + b.sentDown
}

// Call only after the child has exited: toxiproxy accounts a link's bytes when the link closes, and
// even then the flush trails the process, hence the poll for a value that stopped moving.
func proxiedBytes(t *testing.T) int64 {
	t.Helper()
	return settledStoreBytes(t).total()
}

// Only the received counters, so the figures are bytes and not bytes counted twice.
func proxiedBytesByDirection(t *testing.T) (up, down int64) {
	t.Helper()
	b := settledStoreBytes(t)
	return b.receivedUp, b.receivedDown
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
		v := b.total()
		if v == last {
			if same++; same >= stableReads-1 {
				return b
			}
		} else {
			last, same = v, 0
		}
		require.Falsef(t, time.Now().After(give), "toxiproxy's byte counters never settled: last read %d bytes", v)
		time.Sleep(interval)
	}
}

// Filtered to the shaped proxy by label: a sum across both would charge the shipper for every
// assertion the harness makes about it.
func scrapeStoreBytes(t *testing.T) storeBytes {
	t.Helper()
	var b storeBytes
	eachSample(t, metricsURL, scrapePage(t, metricsURL), func(name, labels string, value float64) {
		if name != "toxiproxy_proxy_received_bytes_total" &&
			name != "toxiproxy_proxy_sent_bytes_total" {
			return
		}
		if !strings.Contains(labels, `proxy="`+storeProxyName+`"`) {
			return
		}
		received := name == "toxiproxy_proxy_received_bytes_total"
		switch {
		case strings.Contains(labels, `direction="upstream"`) && received:
			b.receivedUp += int64(value)
		case strings.Contains(labels, `direction="upstream"`):
			b.sentUp += int64(value)
		case strings.Contains(labels, `direction="downstream"`) && received:
			b.receivedDown += int64(value)
		default:
			b.sentDown += int64(value)
		}
	})
	return b
}

// Named here because a pinned MinIO that renamed it would report every run as zero requests.
const s3RequestCountMetric = "minio_api_requests_total"

// A running total like the byte counters, read either side of a child run. Unlike them it counts the
// harness too, so nothing else may run between the two readings.
func s3RequestCount(t *testing.T) int64 {
	t.Helper()
	page := scrapePage(t, minioMetricsURL)
	if !strings.Contains(page, s3RequestCountMetric) {
		t.Fatalf("no %s on %s: the pinned MinIO renamed the counter and every request "+
			"figure would read zero", s3RequestCountMetric, minioMetricsURL)
	}
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
	require.Falsef(t, err != nil, "scrape %s: %v", url, err)
	defer resp.Body.Close()
	require.Falsef(t, resp.StatusCode != http.StatusOK, "scrape %s: HTTP %d", url, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.Falsef(t, err != nil, "read %s: %v", url, err)
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
		require.Falsef(t, !ok, "unparseable sample line from %s: %q", url, line)
		f, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		require.Falsef(t, err != nil, "unparseable sample value in %q: %v", line, err)
		fn(name, labels, f)
	}
}
