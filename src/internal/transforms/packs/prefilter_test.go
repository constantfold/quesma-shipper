package packs

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// containsAny is the independent spec, folding ASCII letter bytes and nothing else.
func containsAny(value string, keywords []string) bool {
	folded := asciiLowered(value)
	for _, k := range keywords {
		if strings.Contains(folded, asciiLowered(k)) {
			return true
		}
	}
	return false
}

// asciiLowered folds ASCII upper-case letter bytes and leaves every other byte as it is.
func asciiLowered(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// The runes Go's case machinery relates to ASCII, all of which keyword matching ignores.
const (
	testDottedI  = "İ" // strings.ToLower gives "i"
	testKelvin   = "K" // strings.ToLower gives "k"
	testLongS    = "ſ" // Go's (?i) folds it with s and S
	testNonASCII = "é" // an ordinary accented letter, no ASCII relation at all
)

// A missing gate silently weakens scrubbing; compare every gate with the independent predicate.
func TestPrefilterAgreesWithContainsAny(t *testing.T) {
	var keywordSets [][]string
	for _, r := range loadedRules(t, PatternPacks...) {
		if len(r.Keywords()) > 0 {
			keywordSets = append(keywordSets, r.Keywords())
		}
	}
	require.Truef(t, len(keywordSets) >= 10, "expected the corpora to carry keyword sets, got %d", len(keywordSets))

	b := NewPrefilterBuilder()
	gates := make([]Gate, len(keywordSets))
	for i, kws := range keywordSets {
		g, err := b.AddKeywords(kws)
		require.NoError(t, err)
		gates[i] = g
	}
	p := b.Build()

	fragments := []string{
		"AKIA", "akia", "AkIa", "aws", "AWS", "sk-", "sk-ant-", "ghp_", "xoxb-",
		"authorization", "AUTHORIZATION", "://", "@", "SG.", "SK", "eyJ",
		"PRIVATE KEY", "private key", "OPENSSH PRIVATE KEY", "AccountKey=",
		"service_account", "hooks.slack.com", "token", "TOKEN", "npm_", "AIza",
		" ", "\n", "x", "0", testDottedI, testKelvin, testLongS, testNonASCII,
		"\xff\xfe", "日本語",
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		var sb strings.Builder
		for n := rng.Intn(12); n >= 0; n-- {
			sb.WriteString(fragments[rng.Intn(len(fragments))])
		}
		value := sb.String()
		seen := p.Scan(value)
		for j, kws := range keywordSets {
			require.Equal(t, containsAny(value, kws), seen.Has(gates[j]), "gate %d (%v) on %q", j, kws, value)
		}
	}
}

// ASCII case flips fire the gate, and the runes Go relates to ASCII do not.
func TestPrefilterFoldsASCIIOnly(t *testing.T) {
	keywords := []string{"apikey", "kubectl"}
	b := NewPrefilterBuilder()
	gate, err := b.AddKeywords(keywords)
	require.NoError(t, err)
	p := b.Build()

	for _, value := range []string{"apikey", "APIKEY", "ApiKey", "KUBECTL", "xxKubectl xx"} {
		seen := p.Scan(value)
		assert.True(t, seen.Has(gate), "gate did not fire on %q", value)
		assert.True(t, containsAny(value, keywords), "containsAny disagrees on %q, the fixture is wrong", value)
	}

	for _, value := range []string{"AP" + testDottedI + "KEY", testKelvin + "UBECTL", "ap" + testLongS + "key"} {
		seen := p.Scan(value)
		assert.False(t, seen.Has(gate), "the fold is ASCII only: a keyword gate must not fire on %q", value)
		assert.False(t, containsAny(value, keywords), "containsAny disagrees on %q, the fixture is wrong", value)
	}
}

func TestPrefilterRejectsNonASCIIKeywords(t *testing.T) {
	b := NewPrefilterBuilder()
	_, err := b.AddKeywords([]string{"ok", "cl" + testNonASCII})
	require.ErrorContains(t, err, "cl"+testNonASCII, "a non-ASCII keyword must fail the build, naming it")
	_, err = b.AddKeywords([]string{""})
	require.Error(t, err, "expected an empty keyword to fail the build")
}
