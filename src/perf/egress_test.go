//go:build perf

// The isolation the rest of the tier assumes, asserted rather than trusted: a tier that stopped
// seeing half the traffic would not fail, it would just report smaller numbers.
package perf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// No working host address, a working proxied route (isolation, not a dead container), and no egress.
func TestTheStoreIsReachableOnlyThroughTheProxy(t *testing.T) {
	ctx := context.Background()

	// The dial, not the lookup: where an engine publishes an address anyway, it must not carry traffic.
	port, err := minioCtr.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Logf("the store published no host port for 9000/tcp: %v", err)
	} else {
		host, err := minioCtr.Host(ctx)
		require.NoError(t, err, "the store's host")
		addr := net.JoinHostPort(host, port.Port())
		conn, dialErr := net.DialTimeout("tcp", addr, 5*time.Second)
		if dialErr == nil {
			conn.Close()
			t.Errorf("the store answered a direct dial on %s: traffic can reach it without "+
				"passing the proxy, and every byte figure in this package is a lower bound", addr)
		} else {
			t.Logf("the store's published address %s does not carry traffic: %v", addr, dialErr)
		}
	}

	resp, err := http.Get(storeEndpoint + "/minio/health/live")
	require.NoError(t, err, "the proxied route to the store is down")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the proxied route to the store")

	// An address, not a name: the claim is about routing, not about docker's resolver.
	code, _, err := minioCtr.Exec(ctx, []string{"curl", "-sS", "--max-time", "5", "http://1.1.1.1/"})
	require.NoError(t, err, "probe the store's egress")
	assert.NotZero(t, code, "the store reached 1.1.1.1 from its own network: the network is not internal, "+
		"and nothing here can claim the shipper's traffic is the only traffic")
}

// A sync whose tickets name a dead second-org endpoint must neither fall back elsewhere nor report success.
func TestASyncAgainstABogusEndpointFailsWithoutFallingBack(t *testing.T) {
	bucket, err := createVersionedBucket(context.Background(),
		fmt.Sprintf("perf-nowhere-%d", time.Now().UnixNano()))
	// Real, so the emptiness assertion below is an answer rather than a NoSuchBucket.
	require.NoError(t, err, "create the second org's bucket")
	w := stageWorldIn(t, "nowhere", deadEndpoint, bucket)
	files := smallCorpusFiles
	stageCorpusFiles(t, w, files)

	before := proxiedBytes(t)
	obs := w.observedSync(t)
	counts := summary(t, obs.Output)
	t.Logf("a sync whose tickets name %s ended %s: shipped %d, failed %d",
		deadEndpoint, obs.exitStatus(), counts["shipped"], counts["failed"])

	assert.Zerof(t, counts["shipped"], "a sync whose tickets name %s reported files shipped:\n%s", deadEndpoint, obs.Output)
	assert.GreaterOrEqualf(t, counts["failed"], files, "a sync whose tickets name %s reported fewer failed files than it "+
		"staged: a file that was neither shipped nor failed went somewhere unaccounted for\n%s", deadEndpoint, obs.Output)
	assert.Zerof(t, proxiedBytes(t)-before, "a sync whose tickets name %s moved bytes through the real store's proxy", deadEndpoint)
	assert.Emptyf(t, w.currentKeys(t), "a sync whose tickets name %s landed objects in %s", deadEndpoint, bucket)
}

// A privileged port: an ephemeral one bound and closed to learn its number is free for anything to take.
const deadEndpoint = "http://127.0.0.1:1"
