//go:build perf

// A synthetic machine and the built binaries, staged for measurement: the protocol tier's staging
// harness copied rather than shared, with the assertions dropped and the timing added. Every world
// is a fresh install, so each owns a subtree and no world counts another's objects.
package perf

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

// Captured before anything overrides HOME: a `go build` under a synthetic HOME re-downloads the module cache.
var realHome = os.Getenv("HOME")

// Fixed, so object keys match across worlds. Published: it protects nothing and must never be used elsewhere.
const (
	testAgeIdentity = "AGE-SECRET-KEY-1JF0Y36Z2RMJNJNN2AYUUF6HMHZVK3FCGK4GUADGRF9M3R57S2UCSDMJWD7"
	testNameKey     = "0101010101010101010101010101010101010101010101010101010101010101"
)

// The pre-filter compares size and mtime, so staged files cannot carry a wall-clock stamp.
var fixtureMTime = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

// The child's view of the machine: the engine sizes its pools off GOMAXPROCS, and the bounds follow it.
const childGOMAXPROCS = 8

// Generous on purpose: a deadlock catcher, not a performance bound.
const syncTimeout = 10 * time.Minute

// One synthetic machine enrolled against the protocol peer and allowed exactly one upload origin.
type world struct {
	Home   string
	Config string // XDG_CONFIG_HOME
	State  string // XDG_STATE_HOME

	installID string // changes with every reset, and keyRoot with it
	org       string
	keyRoot   string

	origin, bucket string // what the tickets this world accepts may name

	binary     string
	gomaxprocs int

	extraEnv []string // appended last, so a scenario's own limit wins
	launcher []string // in front of the binary for a capped run; one that resets the environment carries childVars
}

func stageWorld(t *testing.T) *world {
	t.Helper()
	return stageWorldIn(t, perfOrg, storeEndpoint, perfBucket)
}

// A world whose child sees smokeGOMAXPROCS cores, the machine every smoke scenario runs on.
func stageSmokeWorld(t *testing.T) *world {
	t.Helper()
	w := stageWorld(t)
	w.gomaxprocs = smokeGOMAXPROCS
	return w
}

func stageWorldIn(t *testing.T, org, origin, bucket string) *world {
	t.Helper()
	root := t.TempDir()
	w := &world{
		Home:       filepath.Join(root, "home"),
		Config:     filepath.Join(root, "config"),
		State:      filepath.Join(root, "state"),
		org:        org,
		origin:     origin,
		bucket:     bucket,
		binary:     shipperBinary(t),
		gomaxprocs: childGOMAXPROCS,
	}
	for _, dir := range []string{w.Home, w.Config, w.State} {
		require.NoError(t, os.MkdirAll(dir, 0o700))
	}
	w.reset(t)
	return w
}

// Re-enrolls under a new install id with empty state, making the next run a first sync.
func (w *world) reset(t *testing.T) {
	t.Helper()
	stateDir := filepath.Join(w.State, "trajectory-shipper")
	require.NoError(t, os.RemoveAll(stateDir), "clear the state directory")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	w.installID = uuid.New().String()
	w.keyRoot = "v1/organization=" + w.org + "/install=" + w.installID

	id, err := age.ParseX25519Identity(testAgeIdentity)
	require.NoError(t, err, "the test identity does not parse")
	writeJSON(t, filepath.Join(stateDir, "identity.json"), map[string]any{
		"identity_schema": 1,
		"install_id":      w.installID,
		"age_identity":    testAgeIdentity,
		"age_recipient":   id.Recipient().String(),
		"name_key":        testNameKey,
		"created_at":      fixtureMTime.Format(time.RFC3339),
	})

	// Enrollment is fixture state here: performance measures the shipper, not a control plane.
	pub, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	peer.register(perfInstall{id: w.installID, org: w.org, key: pub, origin: w.origin, bucket: w.bucket})
	writeJSON(t, filepath.Join(stateDir, "enrollment.json"), map[string]any{
		"enrollment_schema": 2,
		"install_id":        w.installID,
		"organization":      w.org,
		"endpoint":          peer.server.URL,
		"device_key":        base64.StdEncoding.EncodeToString(private),
		"enrolled_at":       fixtureMTime.Format(time.RFC3339),
	})

	// Plain HTTP needs the loopback opt-in, and the 64-file default would truncate the corpus.
	configDir := filepath.Join(w.Config, "trajectory-shipper")
	require.NoError(t, os.MkdirAll(configDir, 0o700))
	body := "config_version: 1\n" +
		"max_files_per_run: 100000\n" +
		"upload_targets:\n" +
		"  - origin: " + w.origin + "\n" +
		"    addressing: path-style\n" +
		"    path_prefix: /" + w.bucket + "\n" +
		"    allow_loopback_http: true\n"
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(body), 0o600))
}

// 0600: the shipper refuses identity and enrollment files any wider.
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

var (
	buildOnce   sync.Once
	buildDir    string
	shipperPath string
	buildErr    error
)

// The client under measurement, built once for the whole tier.
func shipperBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		if buildDir, buildErr = os.MkdirTemp("", "shipper-perf"); buildErr != nil {
			return
		}
		shipperPath = filepath.Join(buildDir, "quesma-shipper")
		cmd := exec.Command("go", "build", "-o", shipperPath, "./cmd/quesma-shipper")
		cmd.Dir = ".."
		cmd.Env = append(os.Environ(), "HOME="+realHome)
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build the shipper: %v: %s", err, out)
		}
	})
	require.NoError(t, buildErr)
	return shipperPath
}

// Package level, so there is no t.TempDir to do it: every run would otherwise leak the binary.
func removeBinaries() {
	if buildDir != "" {
		_ = os.RemoveAll(buildDir)
	}
}

// What this world tells the child, and nothing inherited: a launcher such as sudo resets the rest.
func (w *world) childVars() []string {
	return append([]string{
		"HOME=" + w.Home,
		"XDG_CONFIG_HOME=" + w.Config,
		"XDG_STATE_HOME=" + w.State,
		fmt.Sprintf("GOMAXPROCS=%d", w.gomaxprocs),
	}, w.extraEnv...)
}

// This environment minus what would silently retune the run, such as an exported GOMEMLIMIT or SHIPPER_*.
func (w *world) childEnv() []string {
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "HOME", "GOMAXPROCS", "GOMEMLIMIT", "GOGC":
			return true
		}
		return strings.HasPrefix(name, "SHIPPER_") || strings.HasPrefix(name, "XDG_") ||
			strings.HasPrefix(name, "AWS_")
	})
	return append(env, w.childVars()...)
}

// A scenario that needs to survive a failed run uses observedSync directly.
func (w *world) mustSync(t *testing.T) childObservation {
	t.Helper()
	obs := w.observedSync(t)
	require.Falsef(t, obs.Err != nil, "quesma-shipper run --once: %v\n%s", obs.Err, obs.Output)
	return obs
}

// The whole row, in the order the client prints it.
var summaryWords = []string{"shipped", "unchanged", "skipped", "parked", "failed"}

// The run's own counters, from the one line carrying all five words with whole numbers.
func summary(t *testing.T, out string) map[string]int {
	t.Helper()
lines:
	for line := range strings.SplitSeq(out, "\n") {
		counts := map[string]int{}
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if !slices.Contains(summaryWords, fields[i]) {
				continue
			}
			// Atoi rather than Sscanf: "12abc" is not twelve.
			n, err := strconv.Atoi(fields[i+1])
			if err != nil {
				continue lines
			}
			counts[fields[i]] = n
		}
		if len(counts) == len(summaryWords) {
			return counts
		}
	}
	t.Fatalf("no run summary in the output:\n%s", out)
	return nil
}

// Relative to the install root, which changes with every reset.
func (w *world) currentKeys(t *testing.T) []string {
	t.Helper()
	var keys []string
	p := awss3.NewListObjectsV2Paginator(adminS3, &awss3.ListObjectsV2Input{
		Bucket: aws.String(w.bucket),
		Prefix: aws.String(w.keyRoot + "/"),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(context.Background())
		require.NoError(t, err, "list keys")
		for _, o := range page.Contents {
			keys = append(keys, strings.TrimPrefix(aws.ToString(o.Key), w.keyRoot+"/"))
		}
	}
	return keys
}

// Versions per key, keyed relative as above; ListObjectVersions has no generated paginator.
func (w *world) versionCounts(t *testing.T) map[string]int {
	t.Helper()
	counts := map[string]int{}
	in := &awss3.ListObjectVersionsInput{Bucket: aws.String(w.bucket), Prefix: aws.String(w.keyRoot + "/")}
	for {
		out, err := adminS3.ListObjectVersions(context.Background(), in)
		require.NoError(t, err, "list versions")
		for _, v := range out.Versions {
			counts[strings.TrimPrefix(aws.ToString(v.Key), w.keyRoot+"/")]++
		}
		if !aws.ToBool(out.IsTruncated) {
			return counts
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
}

// An unchanged run preserves every transcript version, including the set of transcript keys.
func (w *world) assertTranscriptVersions(t *testing.T, before map[string]int) {
	t.Helper()
	before, after := maps.Clone(before), w.versionCounts(t)
	for _, counts := range []map[string]int{before, after} {
		maps.DeleteFunc(counts, func(key string, _ int) bool { return !strings.Contains(key, transcriptPrefix) })
	}
	assert.Equal(t, before, after, "an unchanged transcript was removed or re-shipped")
}
