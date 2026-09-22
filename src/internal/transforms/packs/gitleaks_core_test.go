package packs

import "testing"

// github-pat is written from GitHub's published token format: a documented prefix, then at least
// 36 letters and digits (30 random plus a 6-character checksum), with no fixed upper length because
// GitHub states token lengths change. Longer tokens must therefore match; shorter must not.
func TestGitHubPATFollowsDocumentedFormat(t *testing.T) {
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
