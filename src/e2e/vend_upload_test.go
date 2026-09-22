// The vend upload path end to end, hermetically: the headers, the refusals, the expiries. What no
// unit test can show is the command tree, config layering, engine loop and uploader agreeing on
// one object's key, headers and bytes.
package e2e

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	seal "github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// Authorize, validate, PUT, commit, judged by what arrived at the store, all a write-only client can get wrong.
func TestVendPathShipsAuthorizedObjectsToTheStore(t *testing.T) {
	v := stageClaudeWorld(t)

	runOneShot(t)
	v.plane.assertClean(t)
	v.plane.assertOneWriter(t)

	mirrors := v.store.mirrorPuts()
	require.NotEmpty(t, mirrors)
	for _, put := range mirrors {
		manifest, _, err := seal.Open(put.Body, v.Identity)
		require.NoError(t, err)
		assert.Truef(t, strings.HasPrefix(put.Key, v.KeyRoot+"/mirror/"), "%s landed outside this install's mirror root %s", put.Key, v.KeyRoot)
		// A header disagreeing with the sealed manifest would mean the two describe different files.
		want := map[string]string{
			"x-amz-meta-source-hash":      manifest.SourceHash,
			"x-amz-meta-source-id":        manifest.SourceID,
			"x-amz-meta-manifest-version": fmt.Sprintf("%d", manifest.ManifestVersion),
			"x-amz-tagging":               "class=trajectory",
		}
		for name, value := range want {
			assert.Equal(t, put.Headers[name], value)
		}
		for _, name := range []string{"x-amz-meta-ticket-id", "x-amz-meta-shipped-hash", "x-amz-meta-artifact-class"} {
			assert.NotEqual(t, "", put.Headers[name])
		}
	}

	// The heartbeat is an ordinary prepared upload under the one state key the protocol allows.
	beats := v.store.heartbeats()
	require.Lenf(t, beats, 1, "the run wrote %d heartbeats, want exactly one", len(beats))
	assert.Equal(t, "heartbeat", beats[0].Headers["x-amz-meta-kind"])
	assert.Equal(t, "class=context", beats[0].Headers["x-amz-tagging"])
	openHeartbeat(t, v, beats[0])
}

// A refused install commits nothing, not even a heartbeat that would report it healthy.
func TestVendPathRefusalStopsTheRunAndTheHeartbeat(t *testing.T) {
	v := stageClaudeWorld(t)
	v.plane.set(func(p *fakePlane) { p.status = http.StatusForbidden })

	out, err := runExpectingFailure(t, "run", "--once")
	require.Errorf(t, err, "a refused authorization exited zero:\n%s", out)
	assert.Containsf(t, out+err.Error(), "refused", "the refusal was not reported as one:\n%s\n%v", out, err)
	require.Len(t, v.store.stored(), 0)

	// Nothing committed, so lifting the refusal ships everything on the next run.
	v.plane.set(func(p *fakePlane) { p.status = http.StatusOK })
	runOneShot(t)
	assert.NotEmpty(t, v.store.mirrorPuts(), "the run after the refusal was lifted shipped nothing")
}

// Preview makes no network call: an authorization would tell the plane about files it did not ship.
func TestVendPathPreviewAuthorizesNothing(t *testing.T) {
	v := stageClaudeWorld(t)

	out := run(t, "preview")
	require.Containsf(t, out, claudeSource, "preview decided nothing, so it proves nothing:\n%s", out)
	assert.Len(t, v.plane.authorizeBatches(), 0)
	assert.Len(t, v.store.stored(), 0)
}

// A ticket that ran out between issue and PUT costs one fresh authorization and nothing else.
func TestVendPathReauthorizesOnceForAnExpiredTicket(t *testing.T) {
	v := stageClaudeWorld(t)
	v.plane.set(func(p *fakePlane) { p.staleBatches = 1 })

	runOneShot(t)
	v.plane.assertClean(t)
	require.NotEmpty(t, v.store.mirrorPuts())

	// Authorized twice, stored once: the reauthorization replaced the dead ticket.
	authorized := map[string]int{}
	for _, batch := range v.plane.authorizeBatches() {
		for _, key := range batch {
			authorized[key]++
		}
	}
	retried := 0
	for _, n := range authorized {
		assert.Truef(t, n <= 2, "a key was authorized %d times; the client reauthorizes at most once", n)
		if n == 2 {
			retried++
		}
	}
	assert.NotEqual(t, 0, retried, "no key was authorized a second time, so no expiry was retried")
	for _, put := range v.store.stored() {
		assert.Equalf(t, 1, v.store.versions(put.Key), "%s was stored more than once; one prepared object is one PUT", put.Key)
	}
}

// doctor's write probe is a real write of the one state object the protocol authorizes.
func TestVendPathDoctorProbesByWritingTheHeartbeat(t *testing.T) {
	v := stageClaudeWorld(t)

	out := run(t, "doctor")
	require.Containsf(t, out, "one test file sent", "doctor's upload probe did not report a successful heartbeat write:\n%s", out)
	assert.NotContainsf(t, out, "preflight", "doctor ran the conditional-write preflight against a write-only path:\n%s", out)
	// Named by origin, never by a spendable ticket URL; `config` still reports the compiled-in write path.
	assert.Containsf(t, out, v.store.server.URL, "doctor did not name the upload destination:\n%s", out)
	assert.Contains(t, run(t, "status"), v.store.server.URL)
	config := run(t, "config")
	assert.Contains(t, config, "vend")
	assert.Contains(t, config, "autoupdate.enabled")
	beats := v.store.heartbeats()
	require.Lenf(t, beats, 1, "the probe wrote %d heartbeats, want exactly one", len(beats))
	// A heartbeat naming no source would report a healthy install as one that found nothing.
	payload := openHeartbeat(t, v, beats[0])
	assert.Containsf(t, payload, claudeSource, "the probe's heartbeat carries no discovery health:\n%s", payload)
	assert.Lenf(t, v.store.mirrorPuts(), 0, "doctor shipped %d trajectory objects; it diagnoses, it does not collect", len(v.store.mirrorPuts()))
}

// Listed origins refuse a plane naming another host. The failed run's heartbeat cannot ship either, so the
// failure must survive on disk and ride a later run, or a machine failing every tick looks idle downstream.
func TestAnUnlistedOriginIsRefusedAndTheFailureRidesTheNextHeartbeat(t *testing.T) {
	v := stageClaudeWorld(t)
	elsewhere := startFakeStore(t)
	v.plane.store = elsewhere

	out, err := runExpectingFailure(t, "run", "--once")
	assert.Error(t, err, "a run whose every upload was refused must not exit zero")
	require.Lenf(t, elsewhere.stored(), 0, "%d objects were sent to an origin no upload_targets entry names", len(elsewhere.stored()))
	require.Lenf(t, v.store.stored(), 0, "%d objects reached the listed origin from tickets naming another", len(v.store.stored()))
	assertEveryObjectFailed(t, out)

	// Recovered: the tickets are good again, and this run's heartbeat carries the earlier failure.
	v.plane.store = v.store
	runOneShot(t)
	beats := v.store.heartbeats()
	require.NotEmpty(t, beats, "the recovered sync shipped no heartbeat")
	payload := openHeartbeat(t, v, beats[len(beats)-1])
	assert.Containsf(t, payload, `"recent_failures"`, "the heartbeat carries no record of the failed run:\n%s", payload)
	assert.Containsf(t, payload, `"kind": "tick_failed"`, "the recorded failure is not classified:\n%s", payload)
	assert.Containsf(t, payload, "shipped nothing", "the recorded failure does not say what went wrong:\n%s", payload)
}

// doctor's probe heartbeat has zeroed file counters, so it must not overwrite the mirror doctor reads.
func TestDoctorsProbeDoesNotOverwriteTheLastFlushMirror(t *testing.T) {
	v := stageClaudeWorld(t)

	runOneShot(t)
	mirror := filepath.Join(statePath(v), "heartbeat.json")
	shipped, err := os.ReadFile(mirror)
	require.NoErrorf(t, err, "a completed sync should have mirrored its heartbeat: %v", err)
	require.Containsf(t, string(shipped), `"shipped"`, "the mirror records no shipped counter:\n%s", shipped)

	run(t, "doctor")

	after, err := os.ReadFile(mirror)
	require.NoErrorf(t, err, "doctor removed the mirror: %v", err)
	assert.Equalf(t, string(shipped), string(after), "doctor's probe overwrote the last flush's mirror.\nbefore:\n%s\nafter:\n%s", shipped, after)
}

// The stranded-fleet regression: with no upload_targets the flush still runs, unpinned and https only, so
// this plaintext store gets nothing and doctor's refusal must name upload_targets.
func TestVendPathRunsUnpinnedWithNoUploadTargets(t *testing.T) {
	v := stageClaudeWorld(t)
	require.NoError(t, os.WriteFile(userConfigPath(v), []byte("config_version: 1\nmax_files_per_run: 10000\n"), 0o600))

	// Non-zero because it sent none of what it prepared, but the flush still RAN.
	out, err := runExpectingFailure(t, "run", "--once")
	assert.Error(t, err, "a run that shipped none of what it prepared must not exit zero")
	require.NotEmptyf(t, v.plane.authorizeBatches(), "the flush aborted before authorizing anything:\n%s", out)
	assertEveryObjectFailed(t, out)

	out, err = runExpectingFailure(t, "doctor")
	assert.Errorf(t, err, "doctor exited zero on an install whose probe cannot land:\n%s", out)
	assert.Truef(t, strings.Contains(out, "upload check failed") && strings.Contains(out, "upload_targets"), "the destination row must name upload_targets:\n%s", out)
	assert.Len(t, v.store.stored(), 0)
	// Preview must still work: it computes everything that would leave and sends none of it.
	assert.Contains(t, run(t, "preview"), claudeSource)
}

// The store would accept another install's key, so the exact-key check is the whole defence against overwrites.
func TestVendPathRefusesATicketNamingAnotherInstallsKey(t *testing.T) {
	v := stageClaudeWorld(t)
	v.plane.set(func(p *fakePlane) { p.misdirect = "00000000-0000-4000-8000-0000000000ff" })

	out, err := runExpectingFailure(t, "run", "--once")
	assert.Error(t, err, "a run whose every ticket was refused must not exit zero")
	require.Len(t, v.store.stored(), 0)
	assertEveryObjectFailed(t, out)
}

// An ordinary per-object failure: nothing commits, and the run reports it rather than stopping.
func assertEveryObjectFailed(t *testing.T, out string) {
	t.Helper()
	if counts := summary(t, out); counts["failed"] == 0 || counts["shipped"] != 0 {
		t.Errorf("the run reported shipped %d failed %d; want every object failed and none shipped:\n%s",
			counts["shipped"], counts["failed"], out)
	}
}

func openHeartbeat(t *testing.T, v *world, put storedPut) string {
	t.Helper()
	_, payload, err := seal.Open(put.Body, v.Identity)
	require.NoError(t, err, "the heartbeat is not a sealed object")
	return string(payload)
}
