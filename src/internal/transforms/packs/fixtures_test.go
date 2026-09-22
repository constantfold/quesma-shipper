package packs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PatternPacks are the high-confidence packs. They scan every field, exempt or not.
var PatternPacks = []string{GitleaksCore, QuesmaExtra, CloudKeys, PIICore}

func loadedRules(t testing.TB, names ...string) []*Rule {
	t.Helper()
	var rules []*Rule
	for _, name := range names {
		loaded, err := Load(name)
		require.NoErrorf(t, err, "Load(%s)", name)
		rules = append(rules, loaded...)
	}
	return rules
}

func ruleByID(t testing.TB, pack, id string) *Rule {
	t.Helper()
	for _, r := range loadedRules(t, pack) {
		if r.id == id {
			return r
		}
	}
	t.Fatalf("%s: %s missing from the pack", pack, id)
	return nil
}

// MatchScanned is MatchScannedIn with a scan of its own.
func (r *Rule) MatchScanned(value string) []Span {
	var scan ValueScan
	scan.Reset(value)
	return r.MatchScannedIn(value, &scan)
}

type probe struct{ in, want string }

// rep repeats alphabet out to exactly n bytes.
func rep(alphabet string, n int) string { return strings.Repeat(alphabet, n/len(alphabet)+1)[:n] }

func alnum(n int) string {
	return rep("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", n)
}

// In tool output, tok must be redacted as one exact span and not must survive.
func tok(s string) probe { return probe{in: "out: " + s + " done", want: s} }
func not(s string) probe { return probe{in: "out: " + s + " done"} }

func checkProbes(t *testing.T, r *Rule, probes []probe) {
	t.Helper()
	for _, p := range probes {
		var matches []string
		for _, s := range r.MatchScanned(p.in) {
			matches = append(matches, p.in[s.Start:s.End])
		}
		var want []string
		if p.want != "" {
			want = []string{p.want}
		}
		assert.Equal(t, want, matches, "%s on %q", r.id, p.in)
	}
}
