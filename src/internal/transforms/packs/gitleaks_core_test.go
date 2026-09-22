package packs

import (
	"strings"
	"testing"
)

// github-pat follows GitHub's published format: a documented prefix, then at least 36 alphanumerics
// and no fixed upper length, since GitHub states token lengths change.
func TestGitHubPATFollowsDocumentedFormat(t *testing.T) {
	alnum := func(n int) string {
		return strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", n/62+1)[:n]
	}
	tok := func(s string) probe { return probe{"out: " + s + " done", s} }
	not := func(s string) probe { return probe{in: "out: " + s + " done"} }
	probes := []probe{
		tok("ghp_" + alnum(36)), tok("gho_" + alnum(36)), tok("ghu_" + alnum(36)),
		tok("ghs_" + alnum(36)), tok("ghr_" + alnum(36)),
		tok("ghp_" + alnum(300)), // no documented upper bound
		not("ghp_" + alnum(35)),
		not("ghx_" + alnum(36)),                  // undocumented prefix
		not("ghp_" + alnum(30) + "-" + alnum(5)), // wrong alphabet
		not("xghp_" + alnum(36)),                 // glued to a word
		not("github_pat_" + alnum(82)),           // the fine-grained rule owns this prefix
	}
	checkProbes(t, ruleByID(t, GitleaksCore, "github-pat"), probes)
}
