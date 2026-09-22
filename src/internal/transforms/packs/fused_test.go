package packs

import (
	"math/rand"
	"reflect"
	"slices"
	"testing"
)

// Two claims the per-rule tests do not make: a rule collecting its slot out of a shared scan
// gets what it would have got alone, and a scan carries nothing from the value before.

// fusedRules returns the loaded rules that have a slot in the shared walk.
func fusedRules(t *testing.T) []*Rule {
	t.Helper()
	var out []*Rule
	for _, r := range loadedRules(t, PIICore) {
		if r.fused != fusedNone {
			out = append(out, r)
		}
	}
	if len(out) != 3 {
		t.Fatalf("expected three fused pii-core rules, got %d", len(out))
	}
	return out
}

// Replays one ValueScan, reused the way the engine reuses it, against the per-rule scanners. Each
// rule in turn triggers the walk, so the others read slots filled by a walk they did not ask for.
func TestFusedScanAgreesWithStandaloneScanners(t *testing.T) {
	rules := fusedRules(t)

	values := slices.Clone(piiEdgeValues)
	rng := rand.New(rand.NewSource(20260817))
	for i := 0; i < 20000; i++ {
		values = append(values, randPIIValue(rng))
	}

	// One scan for the whole run, reset per value: the engine's own lifetime.
	var scan ValueScan
	for _, v := range values {
		for first := range rules {
			scan.Reset(v)
			for k := range rules {
				r := rules[(first+k)%len(rules)]
				want := r.MatchScanned(v)
				got := r.MatchScannedIn(v, &scan)
				if !reflect.DeepEqual(want, got) {
					t.Fatalf("%s on %q after %s asked first: standalone %v, fused %v", r.id, v, rules[first].id, want, got)
				}
			}
		}
	}
}

// A rule with no slot must answer the same whatever the scan holds.
func TestNonFusedRuleIgnoresTheScan(t *testing.T) {
	var scan ValueScan
	scan.Reset("4111111111111111 44051401359 DE89370400440532013000")
	scan.candidates(fusedPESEL) // force the walk, so the slots are non-empty

	for _, r := range loadedRules(t, PIICore) {
		if r.fused != fusedNone {
			continue
		}
		v := "mail jane@example.com and 4111111111111111"
		if want, got := r.MatchScanned(v), r.MatchScannedIn(v, &scan); !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: standalone %v, with a stale scan %v", r.id, want, got)
		}
	}
}
