// The vend upload path end to end, hermetically: the tests whose subject is the path itself (the
// headers, the refusals, the expiries) rather than the collection behaviour it carries. What no
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

// --- the tests ----------------------------------------------------------------

// The whole path in one run: authorize, validate, PUT, commit. Every assertion is about what
// arrived at the store, the only thing a write-only client can get wrong unnoticed.
func TestVendPathShipsAuthorizedObjectsToTheStore(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))

	runOneShot(t)
	v.plane.assertClean(t)
	v.plane.assertOneWriter(t)

	mirrors := v.store.mirrorPuts()
	require.NotEqual(t, 0, len(mirrors))

	for _, put := range mirrors {
		manifest, _, err := seal.Open(put.Body, v.Identity)
		require.NoError(t, err)
		assert.Truef(t, strings.HasPrefix(put.Key, v.KeyRoot+"/mirror/"), "%s landed outside this install's mirror root %s", put.Key, v.KeyRoot)
		// A header disagreeing with the manifest sealed inside would mean the two halves
		// describe different files.
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
	if _, _, err := seal.Open(beats[0].Body, v.Identity); err != nil {
		t.Errorf("the heartbeat is not a sealed object: %v", err)
	}
}

// Progress lives in the local fingerprint document and nowhere else: a second run with nothing
// changed must authorize no trajectory object, or every tick versions every file.
func TestVendPathShipsNothingOnASecondRun(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))
	// Generated observations change each run; this check covers unchanged files.
	writeConfig(t, v, "sources:\n  - id: project-map\n    enabled: false\n  - id: claude-account\n    enabled: false\n")

	runOneShot(t)
	first := len(v.store.mirrorPuts())
	require.NotEqual(t, 0, first, "the first run shipped nothing, so the second proves nothing")

	runOneShot(t)
	assert.Equal(t, len(v.store.mirrorPuts()), first)
	assert.Len(t, shippedFromLog(t, v), 0)
	// The heartbeat is current state, not history: rewritten every run whatever fingerprints say.
	assert.Equal(t, 2, len(v.store.heartbeats()))
	v.plane.assertClean(t)
}

// A refused install stops the run and commits nothing, heartbeat included: writing one would be
// this install's last act reporting itself healthy.
func TestVendPathRefusalStopsTheRunAndTheHeartbeat(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))
	v.plane.setStatus(http.StatusForbidden)

	out, err := runOneShotExpectingFailure(t)
	require.Errorf(t, err, "a refused authorization exited zero:\n%s", out)
	assert.Containsf(t, out+err.Error(), "refused", "the refusal was not reported as one:\n%s\n%v", out, err)
	require.Len(t, v.store.stored(), 0)

	// Nothing committed, so lifting the refusal ships everything on the next run.
	v.plane.setStatus(http.StatusOK)
	runOneShot(t)
	assert.NotEqual(t, 0, len(v.store.mirrorPuts()), "the run after the refusal was lifted shipped nothing")
}

// Preview makes no network call: an authorization from it would tell the control plane about
// files this machine deliberately did not ship.
func TestVendPathPreviewAuthorizesNothing(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))

	out := run(t, "preview")
	require.Containsf(t, out, claudeSource, "preview decided nothing, so it proves nothing:\n%s", out)
	assert.Len(t, v.plane.authorizeBatches(), 0)
	assert.Len(t, v.store.stored(), 0)
}

// A ticket that ran out between issue and PUT costs one fresh authorization and nothing else: an
// expiry is a slow upload, not a reason to leave the file for the next tick.
func TestVendPathReauthorizesOnceForAnExpiredTicket(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))
	v.plane.mu.Lock()
	v.plane.staleBatches = 1
	v.plane.mu.Unlock()

	runOneShot(t)
	v.plane.assertClean(t)

	mirrors := v.store.mirrorPuts()
	require.NotEqual(t, 0, len(mirrors))
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
	stored := map[string]int{}
	for _, put := range v.store.stored() {
		stored[put.Key]++
	}
	for key, n := range stored {
		assert.Equalf(t, 1, n, "%s was stored %d times; one prepared object is one PUT", key, n)
	}
}

// doctor has nothing to read back here, so its write probe is a real write of the one state
// object the protocol authorizes.
func TestVendPathDoctorProbesByWritingTheHeartbeat(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))

	out := run(t, "doctor")
	// No conditional-write preflight exists on a write-only path.
	require.Containsf(t, out, "one test file sent", "doctor's upload probe did not report a successful heartbeat write:\n%s", out)
	assert.NotContainsf(t, out, "preflight", "doctor ran the conditional-write preflight against a write-only path:\n%s", out)
	// Named by origin and never by a ticket URL, which anyone holding it could spend. Both
	// printing paths answer: doctor holds a live runtime, status the configuration alone.
	assert.Containsf(t, out, v.store.server.URL, "doctor did not name the upload destination:\n%s", out)
	assert.Contains(t, run(t, "status"), v.store.server.URL)
	beats := v.store.heartbeats()
	require.Lenf(t, beats, 1, "the probe wrote %d heartbeats, want exactly one", len(beats))
	// A heartbeat naming no source would report a healthy install as one that found nothing.
	_, payload, err := seal.Open(beats[0].Body, v.Identity)
	require.NoErrorf(t, err, "the probe's heartbeat is not a sealed object: %v", err)
	assert.Containsf(t, string(payload), claudeSource, "the probe's heartbeat carries no discovery health:\n%s", payload)
	assert.Lenf(t, v.store.mirrorPuts(), 0, "doctor shipped %d trajectory objects; it diagnoses, it does not collect", len(v.store.mirrorPuts()))
}

// The whole point of persisting the tick outcome: a failed run uploads nothing, its own heartbeat
// included, so the failure has to survive on disk and ride a later run that can ship. Without this
// a machine that fails every tick is indistinguishable downstream from an idle one.
func TestAFailedRunsFailureRidesTheNextHeartbeat(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))

	// Every ticket names an origin no upload_targets entry admits, so the run ships nothing.
	elsewhere := startFakeStore(t)
	v.plane.store = elsewhere
	if _, err := runOneShotExpectingFailure(t); err == nil {
		t.Fatal("the staged sync was supposed to fail")
	}
	require.Len(t, v.store.heartbeats(), 0, "a run whose uploads all failed managed to ship a heartbeat")

	// Recovered: the tickets are good again, and this run's heartbeat carries the earlier failure.
	v.plane.store = v.store
	runOneShot(t)

	beats := v.store.heartbeats()
	require.NotEqual(t, 0, len(beats), "the recovered sync shipped no heartbeat")
	_, payload, err := seal.Open(beats[len(beats)-1].Body, v.Identity)
	require.NoErrorf(t, err, "the heartbeat is not a sealed object: %v", err)
	assert.Containsf(t, string(payload), `"recent_failures"`, "the heartbeat carries no record of the failed run:\n%s", payload)
	assert.Containsf(t, string(payload), `"kind": "tick_failed"`, "the recorded failure is not classified:\n%s", payload)
	assert.Containsf(t, string(payload), "shipped nothing", "the recorded failure does not say what went wrong:\n%s", payload)
}

// doctor reads the local heartbeat mirror to answer "did anything leave this machine", and its
// own probe writes a heartbeat with every file counter zeroed. If the probe mirrored that, running
// the diagnostic would destroy the evidence and the next doctor would report a shipping install as
// one with nothing to ship.
func TestDoctorsProbeDoesNotOverwriteTheLastFlushMirror(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))

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

// The one write path is compiled in, so no config names it, and the verbs an operator reaches for
// first must agree: disagreement is how a machine's real behaviour becomes unknowable.
func TestVendPathIsCompiledInAndReportedByTheReadOnlyVerbs(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))
	writeConfig(t, v, "")

	runOneShot(t)
	v.plane.assertClean(t)
	require.NotEqual(t, 0, len(v.store.mirrorPuts()))
	// The read-only verbs must resolve the same document.
	assert.Contains(t, run(t, "status"), v.store.server.URL)
	assert.Contains(t, run(t, "config"), "vend")
}

// The stranded-fleet regression: an enrolled install with no upload_targets must still run the
// flush rather than abort before the first network call. Nothing lands in this world because the
// store is plaintext http, which unpinned mode refuses per object.
func TestVendPathRunsUnpinnedWithNoUploadTargets(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))
	writeConfigWithoutUploadTargets(t, v)

	// Non-zero because it sent none of what it prepared, but the flush still RAN: the point of
	// this regression is that it reaches the network at all, which the summary below proves.
	out, err := runOneShotExpectingFailure(t)
	assert.Error(t, err, "a run that shipped none of what it prepared must not exit zero")
	require.NotEqualf(t, 0, len(v.plane.authorizeBatches()), "the flush aborted before authorizing anything:\n%s", out)
	assert.Len(t, v.store.stored(), 0)
	if counts := summary(t, out); counts["failed"] == 0 || counts["shipped"] != 0 {
		t.Errorf("the run reported shipped %d failed %d; want every object refused per-object",
			counts["shipped"], counts["failed"])
	}
}

// The unpinned probe fails only on this world's plaintext store, and the refusal must name
// upload_targets as the way to admit one.
func TestVendPathDoctorReportsAnInstallWithNoUploadTargets(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))
	writeConfigWithoutUploadTargets(t, v)

	out, err := runExpectingFailure(t, "doctor")
	assert.Errorf(t, err, "doctor exited zero on an install whose probe cannot land:\n%s", out)
	// The destination row carries the refusal, and the refusal names the setting.
	assert.Truef(t, strings.Contains(out, "upload check failed") && strings.Contains(out, "upload_targets"), "the destination row must name upload_targets:\n%s", out)
	assert.Len(t, v.store.stored(), 0)
	// Preview must still work: it computes everything that would leave and sends none of it.
	assert.Contains(t, run(t, "preview"), claudeSource)
}

// A ticket for the right origin and another install's key is refused before any byte is sent: the
// store would accept it, so the exact-key check is the whole defence against overwrites.
func TestVendPathRefusesATicketNamingAnotherInstallsKey(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))
	v.plane.mu.Lock()
	v.plane.misdirect = "00000000-0000-4000-8000-0000000000ff"
	v.plane.mu.Unlock()

	out, err := runOneShotExpectingFailure(t)
	assert.Error(t, err, "a run whose every ticket was refused must not exit zero")
	require.Len(t, v.store.stored(), 0)
	if counts := summary(t, out); counts["failed"] == 0 || counts["shipped"] != 0 {
		t.Errorf("the run reported shipped %d failed %d; want every object failed and none shipped",
			counts["shipped"], counts["failed"])
	}
}

// Once the machine owner lists origins, a control plane naming another host must get nothing.
func TestVendPathRefusesATicketForAnUnlistedOrigin(t *testing.T) {
	v := stageWorld(t)
	stageClaude(t, v, realUsername(t))

	elsewhere := startFakeStore(t)
	v.plane.store = elsewhere

	// Non-zero: every upload failed, so the run shipped nothing. Exiting clean having sent none of
	// what it prepared is the outage shape this exit code exists to surface.
	out, err := runOneShotExpectingFailure(t)
	assert.Error(t, err, "a run whose every upload was refused must not exit zero")
	require.Lenf(t, elsewhere.stored(), 0, "%d objects were sent to an origin no upload_targets entry names", len(elsewhere.stored()))
	require.Lenf(t, v.store.stored(), 0, "%d objects reached the listed origin from tickets naming another", len(v.store.stored()))
	// An ordinary per-object failure: nothing commits, the run reports it rather than stopping.
	if counts := summary(t, out); counts["failed"] == 0 || counts["shipped"] != 0 {
		t.Errorf("the run reported shipped %d failed %d; want every object failed and none shipped",
			counts["shipped"], counts["failed"])
	}
}
