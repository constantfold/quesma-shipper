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

	"github.com/stretchr/testify/require"

	seal "github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// --- the tests ----------------------------------------------------------------

// The whole path in one run: authorize, validate, PUT, commit. Every assertion is about what
// arrived at the store, the only thing a write-only client can get wrong unnoticed.
func TestVendPathShipsAuthorizedObjectsToTheStore(t *testing.T) {
	v := stageClaudeWorld(t)

	runOneShot(t)
	v.plane.assertClean(t)
	v.plane.assertOneWriter(t)

	mirrors := v.store.mirrorPuts()
	if len(mirrors) == 0 {
		t.Fatalf("nothing reached the object store; authorize batches: %v", v.plane.authorizeBatches())
	}

	for _, put := range mirrors {
		manifest, _, err := seal.Open(put.Body, v.Identity)
		if err != nil {
			t.Fatalf("%s: the stored bytes are not the sealed object: %v", put.Key, err)
		}
		if !strings.HasPrefix(put.Key, v.KeyRoot+"/mirror/") {
			t.Errorf("%s landed outside this install's mirror root %s", put.Key, v.KeyRoot)
		}
		// A header disagreeing with the manifest sealed inside would mean the two halves
		// describe different files.
		want := map[string]string{
			"x-amz-meta-source-hash":      manifest.SourceHash,
			"x-amz-meta-source-id":        manifest.SourceID,
			"x-amz-meta-manifest-version": fmt.Sprintf("%d", manifest.ManifestVersion),
			"x-amz-tagging":               "class=trajectory",
		}
		for name, value := range want {
			if got := put.Headers[name]; got != value {
				t.Errorf("%s: header %s is %q, want %q", put.Key, name, got, value)
			}
		}
		for _, name := range []string{"x-amz-meta-ticket-id", "x-amz-meta-shipped-hash", "x-amz-meta-artifact-class"} {
			if put.Headers[name] == "" {
				t.Errorf("%s: header %s did not arrive", put.Key, name)
			}
		}
	}

	// The heartbeat is an ordinary prepared upload under the one state key the protocol allows.
	beats := v.store.heartbeats()
	if len(beats) != 1 {
		t.Fatalf("the run wrote %d heartbeats, want exactly one", len(beats))
	}
	if got := beats[0].Headers["x-amz-meta-kind"]; got != "heartbeat" {
		t.Errorf("the heartbeat arrived with kind %q", got)
	}
	if got := beats[0].Headers["x-amz-tagging"]; got != "class=context" {
		t.Errorf("the heartbeat arrived tagged %q", got)
	}
	openHeartbeat(t, v, beats[0])
}

// A refused install stops the run and commits nothing, heartbeat included: writing one would be
// this install's last act reporting itself healthy.
func TestVendPathRefusalStopsTheRunAndTheHeartbeat(t *testing.T) {
	v := stageClaudeWorld(t)
	v.plane.set(func(p *fakePlane) { p.status = http.StatusForbidden })

	out, err := runExpectingFailure(t, "run", "--once")
	if err == nil {
		t.Fatalf("a refused authorization exited zero:\n%s", out)
	}
	if !strings.Contains(out+err.Error(), "refused") {
		t.Errorf("the refusal was not reported as one:\n%s\n%v", out, err)
	}
	if got := v.store.stored(); len(got) != 0 {
		t.Fatalf("%d objects reached the store under a refusal", len(got))
	}

	// Nothing committed, so lifting the refusal ships everything on the next run.
	v.plane.set(func(p *fakePlane) { p.status = http.StatusOK })
	runOneShot(t)
	if len(v.store.mirrorPuts()) == 0 {
		t.Error("the run after the refusal was lifted shipped nothing")
	}
}

// Preview makes no network call: an authorization from it would tell the control plane about
// files this machine deliberately did not ship.
func TestVendPathPreviewAuthorizesNothing(t *testing.T) {
	v := stageClaudeWorld(t)

	out := run(t, "preview")
	if !strings.Contains(out, claudeSource) {
		t.Fatalf("preview decided nothing, so it proves nothing:\n%s", out)
	}
	if batches := v.plane.authorizeBatches(); len(batches) != 0 {
		t.Errorf("preview authorized %d batches: %v", len(batches), batches)
	}
	if got := v.store.stored(); len(got) != 0 {
		t.Errorf("preview uploaded %d objects", len(got))
	}
}

// A ticket that ran out between issue and PUT costs one fresh authorization and nothing else: an
// expiry is a slow upload, not a reason to leave the file for the next tick.
func TestVendPathReauthorizesOnceForAnExpiredTicket(t *testing.T) {
	v := stageClaudeWorld(t)
	v.plane.set(func(p *fakePlane) { p.staleBatches = 1 })

	runOneShot(t)
	v.plane.assertClean(t)

	mirrors := v.store.mirrorPuts()
	if len(mirrors) == 0 {
		t.Fatalf("the expired first batch was never retried; authorize batches: %v",
			v.plane.authorizeBatches())
	}
	// Authorized twice, stored once: the reauthorization replaced the dead ticket.
	authorized := map[string]int{}
	for _, batch := range v.plane.authorizeBatches() {
		for _, key := range batch {
			authorized[key]++
		}
	}
	retried := 0
	for _, n := range authorized {
		if n > 2 {
			t.Errorf("a key was authorized %d times; the client reauthorizes at most once", n)
		}
		if n == 2 {
			retried++
		}
	}
	if retried == 0 {
		t.Error("no key was authorized a second time, so no expiry was retried")
	}
	for _, put := range v.store.stored() {
		if n := v.store.versions(put.Key); n != 1 {
			t.Errorf("%s was stored %d times; one prepared object is one PUT", put.Key, n)
		}
	}
}

// doctor has nothing to read back here, so its write probe is a real write of the one state
// object the protocol authorizes.
func TestVendPathDoctorProbesByWritingTheHeartbeat(t *testing.T) {
	v := stageClaudeWorld(t)

	out := run(t, "doctor")
	// No conditional-write preflight exists on a write-only path.
	if !strings.Contains(out, "one test file sent") {
		t.Fatalf("doctor's upload probe did not report a successful heartbeat write:\n%s", out)
	}
	if strings.Contains(out, "preflight") {
		t.Errorf("doctor ran the conditional-write preflight against a write-only path:\n%s", out)
	}
	// Named by origin and never by a ticket URL, which anyone holding it could spend. Both
	// printing paths answer: doctor holds a live runtime, status the configuration alone.
	if !strings.Contains(out, v.store.server.URL) {
		t.Errorf("doctor did not name the upload destination:\n%s", out)
	}
	if status := run(t, "status"); !strings.Contains(status, v.store.server.URL) {
		t.Errorf("status did not name the upload destination:\n%s", status)
	}
	// The one write path is compiled in, so no config names it; config show must still report it,
	// and the update switch an operator verifies before trusting a fleet not to self-update.
	config := run(t, "config")
	for _, want := range []string{"vend", "autoupdate.enabled"} {
		if !strings.Contains(config, want) {
			t.Errorf("config show does not report %q:\n%s", want, config)
		}
	}
	beats := v.store.heartbeats()
	if len(beats) != 1 {
		t.Fatalf("the probe wrote %d heartbeats, want exactly one", len(beats))
	}
	// A heartbeat naming no source would report a healthy install as one that found nothing.
	payload := openHeartbeat(t, v, beats[0])
	if !strings.Contains(string(payload), claudeSource) {
		t.Errorf("the probe's heartbeat carries no discovery health:\n%s", payload)
	}
	if len(v.store.mirrorPuts()) != 0 {
		t.Errorf("doctor shipped %d trajectory objects; it diagnoses, it does not collect",
			len(v.store.mirrorPuts()))
	}
}

// Once the machine owner lists origins, a control plane naming another host must get nothing. The
// whole point of persisting the tick outcome: a failed run uploads nothing, its own heartbeat
// included, so the failure has to survive on disk and ride a later run that can ship. Without this
// a machine that fails every tick is indistinguishable downstream from an idle one.
func TestAFailedRunsFailureRidesTheNextHeartbeat(t *testing.T) {
	v := stageClaudeWorld(t)

	// Every ticket names an origin no upload_targets entry admits, so the run ships nothing.
	elsewhere := startFakeStore(t)
	v.plane.store = elsewhere
	out, err := runExpectingFailure(t, "run", "--once")
	if err == nil {
		t.Error("a run whose every upload was refused must not exit zero")
	}
	if len(elsewhere.stored()) != 0 {
		t.Fatalf("%d objects were sent to an origin no upload_targets entry names", len(elsewhere.stored()))
	}
	if len(v.store.stored()) != 0 {
		t.Fatalf("%d objects reached the listed origin from tickets naming another", len(v.store.stored()))
	}
	assertEveryObjectFailed(t, out)

	// Recovered: the tickets are good again, and this run's heartbeat carries the earlier failure.
	v.plane.store = v.store
	runOneShot(t)

	beats := v.store.heartbeats()
	if len(beats) == 0 {
		t.Fatal("the recovered sync shipped no heartbeat")
	}
	payload := openHeartbeat(t, v, beats[len(beats)-1])
	if !strings.Contains(string(payload), `"recent_failures"`) {
		t.Errorf("the heartbeat carries no record of the failed run:\n%s", payload)
	}
	if !strings.Contains(string(payload), `"kind": "tick_failed"`) {
		t.Errorf("the recorded failure is not classified:\n%s", payload)
	}
	if !strings.Contains(string(payload), "shipped nothing") {
		t.Errorf("the recorded failure does not say what went wrong:\n%s", payload)
	}
}

// doctor reads the local heartbeat mirror to answer "did anything leave this machine", and its
// own probe writes a heartbeat with every file counter zeroed. If the probe mirrored that, running
// the diagnostic would destroy the evidence and the next doctor would report a shipping install as
// one with nothing to ship.
func TestDoctorsProbeDoesNotOverwriteTheLastFlushMirror(t *testing.T) {
	v := stageClaudeWorld(t)

	runOneShot(t)
	mirror := filepath.Join(statePath(v), "heartbeat.json")
	shipped, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatalf("a completed sync should have mirrored its heartbeat: %v", err)
	}
	if !strings.Contains(string(shipped), `"shipped"`) {
		t.Fatalf("the mirror records no shipped counter:\n%s", shipped)
	}

	run(t, "doctor")

	after, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatalf("doctor removed the mirror: %v", err)
	}
	if string(after) != string(shipped) {
		t.Errorf("doctor's probe overwrote the last flush's mirror.\nbefore:\n%s\nafter:\n%s", shipped, after)
	}
}

// The stranded-fleet regression: an enrolled install with no upload_targets must still run the
// flush rather than abort before the first network call. Nothing lands in this world because the
// store is plaintext http, which unpinned mode refuses per object, and doctor's refusal must name
// upload_targets as the way to admit one.
func TestVendPathRunsUnpinnedWithNoUploadTargets(t *testing.T) {
	v := stageClaudeWorld(t)
	require.NoError(t, os.WriteFile(userConfigPath(v), []byte("config_version: 1\nmax_files_per_run: 10000\n"), 0o600))

	// Non-zero because it sent none of what it prepared, but the flush still RAN: the point of
	// this regression is that it reaches the network at all, which the summary below proves.
	out, err := runExpectingFailure(t, "run", "--once")
	if err == nil {
		t.Error("a run that shipped none of what it prepared must not exit zero")
	}
	if len(v.plane.authorizeBatches()) == 0 {
		t.Fatalf("the flush aborted before authorizing anything:\n%s", out)
	}
	assertEveryObjectFailed(t, out)

	out, err = runExpectingFailure(t, "doctor")
	if err == nil {
		t.Errorf("doctor exited zero on an install whose probe cannot land:\n%s", out)
	}
	// The destination row carries the refusal, and the refusal names the setting.
	if !strings.Contains(out, "upload check failed") || !strings.Contains(out, "upload_targets") {
		t.Errorf("the destination row must name upload_targets:\n%s", out)
	}
	if got := v.store.stored(); len(got) != 0 {
		t.Errorf("%d objects reached the store over a refused scheme", len(got))
	}
	// Preview must still work: it computes everything that would leave and sends none of it.
	if preview := run(t, "preview"); !strings.Contains(preview, claudeSource) {
		t.Errorf("preview stopped working on an install with no upload path:\n%s", preview)
	}
}

// A ticket for the right origin and another install's key is refused before any byte is sent: the
// store would accept it, so the exact-key check is the whole defence against overwrites.
func TestVendPathRefusesATicketNamingAnotherInstallsKey(t *testing.T) {
	v := stageClaudeWorld(t)
	v.plane.set(func(p *fakePlane) { p.misdirect = "00000000-0000-4000-8000-0000000000ff" })

	out, err := runExpectingFailure(t, "run", "--once")
	if err == nil {
		t.Error("a run whose every ticket was refused must not exit zero")
	}
	if got := v.store.stored(); len(got) != 0 {
		t.Fatalf("%d objects were written under a key this install did not prepare: %s",
			len(got), got[0].Key)
	}
	assertEveryObjectFailed(t, out)
}

// An ordinary per-object failure: nothing commits, the run reports it rather than stopping.
func assertEveryObjectFailed(t *testing.T, out string) {
	t.Helper()
	if counts := summary(t, out); counts["failed"] == 0 || counts["shipped"] != 0 {
		t.Errorf("the run reported shipped %d failed %d; want every object failed and none shipped",
			counts["shipped"], counts["failed"])
	}
}

func openHeartbeat(t *testing.T, v *world, put storedPut) []byte {
	t.Helper()
	_, payload, err := seal.Open(put.Body, v.Identity)
	if err != nil {
		t.Fatalf("the heartbeat is not a sealed object: %v", err)
	}
	return payload
}
