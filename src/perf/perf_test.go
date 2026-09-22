//go:build perf

// Package perf measures how a sync behaves when the store is far away: Toxiproxy shapes the link to
// a MinIO that sits alone on an internal network, so every shipper byte is on a counter while the
// harness's own admin traffic goes over a second, never-shaped proxy. Bounds are ratios or multiples
// of the injected RTT, never absolute times, and the toxic shapes delay only, not bandwidth or loss.
package perf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	toxiproxy "github.com/Shopify/toxiproxy/v2/client"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/testcontainers/testcontainers-go"

	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Fixed versions: a floating MinIO changes concurrency behaviour, a floating toxiproxy its metric names.
const (
	minioImage     = "pgsty/silo:RELEASE.2026-09-03T13-18-01Z"
	toxiproxyImage = "ghcr.io/shopify/toxiproxy:2.12.0"
)

const (
	// How toxiproxy reaches MinIO; there is no host-mapped alternative, which is the point.
	minioUpstream = "minio:9000"

	// The shipper's listener and the harness's: any ports but 8474, which is the API.
	proxyListenPort  = "8666"
	adminListenPort  = "8667"
	toxiproxyAPIPort = "8474"

	// Separate label sets in the metrics, so the byte counters answer for the shipper alone.
	storeProxyName = "minio"
	adminProxyName = "minio-admin"
)

var (
	minioCtr *tcminio.MinioContainer

	// Lists over the unshaped admin proxy, so its traffic never lands on the shipper's counters.
	adminS3 *awss3.Client

	// The shipper's route: the origin every ticket is presigned against.
	storeEndpoint string

	// The one bucket this tier writes to; worlds are separated by install root, not by bucket.
	perfBucket string

	toxi       *toxiproxy.Client
	storeProxy *toxiproxy.Proxy

	// The proxy's control API, its exposition page, and MinIO's own.
	toxiAPIURL      string
	metricsURL      string
	minioMetricsURL string
)

func TestMain(m *testing.M) {
	// Before any container: this binary is what probeMemoryCap re-executes as the hog.
	if spec, ok := os.LookupEnv(memoryHogEnv); ok {
		os.Exit(runMemoryHog(spec))
	}
	os.Exit(run(m))
}

// Exists so the teardown can be a defer: TestMain cannot have one, since os.Exit does not unwind.
func run(m *testing.M) int {
	ctx := context.Background()
	fail := func(what string, err error) int {
		fmt.Fprintf(os.Stderr, "perf: %s: %v\n", what, err)
		return 1
	}
	warn := func(what string, err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "perf: %s: %v\n", what, err)
		}
	}
	defer removeCorpusMaster()
	defer removeBinaries()

	// internalNet has no NAT and no default route; toxiproxy is the only container on both.
	edgeNet, err := network.New(ctx)
	if err != nil {
		return fail("create the edge network", err)
	}
	defer func() { warn("remove the edge network", edgeNet.Remove(ctx)) }()
	internalNet, err := network.New(ctx, network.WithInternal())
	if err != nil {
		return fail("create the internal network", err)
	}
	defer func() { warn("remove the internal network", internalNet.Remove(ctx)) }()

	minio, err := tcminio.Run(ctx, minioImage,
		network.WithNetwork([]string{"minio"}, internalNet),
		// Public scrape auth for the S3 request count; CI_CD drops preallocation that would crowd the memory budgets.
		testcontainers.WithEnv(map[string]string{"MINIO_PROMETHEUS_AUTH_TYPE": "public", "CI_CD": "true"}),
		// The internal-only store has no host port, so wait on its ready log.
		testcontainers.WithWaitStrategy(wait.ForLog("API:").WithStartupTimeout(2*time.Minute)),
	)
	defer func() { warn("terminate MinIO", testcontainers.TerminateContainer(minio)) }()
	if err != nil {
		return fail("start MinIO", err)
	}
	minioCtr = minio

	// Not modules/toxiproxy: its own -config cannot be combined with -proxy-metrics.
	proxyCtr, err := testcontainers.Run(ctx, toxiproxyImage,
		// The edge network first: a container created on an internal one gets no port bindings (moby #36174).
		network.WithNetwork([]string{"toxiproxy"}, edgeNet),
		network.WithNetwork([]string{"toxiproxy"}, internalNet),
		testcontainers.WithExposedPorts(
			toxiproxyAPIPort+"/tcp", proxyListenPort+"/tcp", adminListenPort+"/tcp"),
		// The image defaults the API to localhost, which from outside the container is nothing.
		testcontainers.WithCmd("-host=0.0.0.0", "-proxy-metrics"),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/version").WithPort(toxiproxyAPIPort+"/tcp")),
	)
	defer func() { warn("terminate toxiproxy", testcontainers.TerminateContainer(proxyCtr)) }()
	if err != nil {
		return fail("start toxiproxy", err)
	}

	var addrs [3]string
	for i, port := range []string{toxiproxyAPIPort, proxyListenPort, adminListenPort} {
		if addrs[i], err = hostAddr(ctx, proxyCtr, port); err != nil {
			return fail("toxiproxy address for port "+port, err)
		}
	}
	apiAddr, adminEndpoint := addrs[0], "http://"+addrs[2]
	toxiAPIURL = "http://" + apiAddr
	metricsURL = toxiAPIURL + "/metrics"
	storeEndpoint = "http://" + addrs[1]
	// v3, not v2: v2 serves a ten-second cached snapshot, too stale to read around a sub-second run.
	minioMetricsURL = adminEndpoint + "/minio/metrics/v3/api/requests"

	toxi = toxiproxy.NewClient(apiAddr)
	// 0.0.0.0 so the mapped port reaches it; the docker alias upstream, resolved on the internal net.
	if storeProxy, err = toxi.CreateProxy(storeProxyName, "0.0.0.0:"+proxyListenPort, minioUpstream); err != nil {
		return fail("create the store proxy", err)
	}
	// The harness's own route: never shaped, and its bytes carry a different label.
	if _, err := toxi.CreateProxy(adminProxyName, "0.0.0.0:"+adminListenPort, minioUpstream); err != nil {
		return fail("create the admin proxy", err)
	}

	adminS3 = awss3.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(minio.Username, minio.Password, ""),
	}, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(adminEndpoint)
		o.UsePathStyle = true
	})

	// Minted before the protocol peer starts, because it signs the tickets used by the measured path.
	if err := mintIngestUser(ctx, minio); err != nil {
		return fail("mint the write-only ingestion user", err)
	}
	if perfBucket, err = createVersionedBucket(ctx, fmt.Sprintf("perf-%d", time.Now().UnixNano())); err != nil {
		return fail("create the bucket", err)
	}
	startProtocolPeer()
	defer peer.server.Close()

	code := m.Run()
	if code != 0 {
		dumpProxyState()
	}
	return code
}

// Mirror objects are overwritten in place, so "the steady-state run added no versions" needs versioning.
func createVersionedBucket(ctx context.Context, name string) (string, error) {
	if _, err := adminS3.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(name)}); err != nil {
		return "", err
	}
	_, err := adminS3.PutBucketVersioning(ctx, &awss3.PutBucketVersioningInput{
		Bucket:                  aws.String(name),
		VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled},
	})
	return name, err
}

// On failure, whether a toxic was attached is the first question, and its answer dies with the container.
func dumpProxyState() {
	path := filepath.Join(resultsDir(), "toxiproxy-state.json")
	err := func() error {
		resp, err := http.Get(toxiAPIURL + "/proxies")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		return os.WriteFile(path, body, 0o600)
	}()
	if err != nil {
		fmt.Fprintf(os.Stderr, "perf: save the proxy state to %s: %v\n", path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "perf: the proxies and their toxics as they were at the end: %s\n", path)
}

func hostAddr(ctx context.Context, c testcontainers.Container, port string) (string, error) {
	host, err := c.Host(ctx)
	if err != nil {
		return "", err
	}
	mapped, err := c.MappedPort(ctx, port+"/tcp")
	if err != nil {
		return "", err
	}
	return host + ":" + mapped.Port(), nil
}

// Half per direction, because the toxic delays one stream and a request-response pair crosses both.
func withLatency(t *testing.T, rtt time.Duration) {
	t.Helper()
	for _, stream := range []string{"upstream", "downstream"} {
		_, err := storeProxy.AddToxic("latency_"+stream, "latency", stream, 1,
			toxiproxy.Attributes{"latency": (rtt / 2).Milliseconds()})
		require.NoErrorf(t, err, "add %s latency toxic", stream)
	}
	// /reset removes every toxic and re-enables every proxy, however the test exits.
	t.Cleanup(func() {
		if err := toxi.ResetState(); err != nil {
			t.Errorf("reset toxiproxy: %v", err)
		}
	})

	// A full request, not a dial: the toxic delays data, so a connect-only probe would pass unshaped.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 30 * time.Second}
	start := time.Now()
	resp, err := client.Get(storeEndpoint + "/minio/health/live")
	require.NoError(t, err, "probe the shaped link")
	resp.Body.Close()
	elapsed := time.Since(start)
	if elapsed < rtt*3/4 {
		t.Fatalf("a round trip through the proxy took %v with %v of latency configured; "+
			"the toxic is not on the wire and every timing below would be meaningless", elapsed, rtt)
	}
	t.Logf("shaping live: %v round trip at %v configured rtt", elapsed.Round(time.Millisecond), rtt)
}
