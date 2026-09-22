package cursorjoin_test

import "testing"

// Tool-specific shapes of the stored arguments: what they must not match, and what they still must.
func TestToolArgumentShapes(t *testing.T) {
	runJoinCases(t, []joinCase{{
		// A directory path is a prefix of every file under it, so substring evidence matched a search
		// of a directory to a read of a file inside it.
		name:       "a directory argument does not match a file beneath it",
		query:      "audit the config package",
		transcript: turn(use("Grep", `{"pattern":"deny_additions","path":"/work/api/internal/config"}`), use("Read", `{"path":"/work/api/internal/config/resolve.go"}`)),
		bubbles: []storeRow{
			toolRow("grep", "ripgrep_raw_search", `{}`, "resolve.go:41"),
			toolRow("read", "read_file_v2", `{"path":"/work/api/internal/config/resolve.go"}`, "package config"),
		},
		want: map[int][]string{1: {"grep", "read"}},
	}, {
		// Cursor splices its attribution into what ran; unstripped, that scores as contradiction.
		name:  "a vendor-rewritten command still aligns",
		query: "commit and open a PR",
		transcript: turn(use("Shell", `{"command":"git commit -m \"fix: bound the loader\"","description":"Commit the fix"}`),
			use("Shell", `{"command":"gh pr create --title \"Bound the loader\" --body \"$(cat <<'EOB'\n## Summary\n- bound it\nEOB\n)\"","description":"Open the PR"}`)),
		bubbles: []storeRow{
			tool{id: "commit", name: "run_terminal_command_v2", result: "1 file changed",
				params: `{"command":"git commit --trailer \"Co-authored-by: Cursor <cursoragent@cursor.com>\" -m \"fix: bound the loader\""}`}.row(),
			tool{id: "pr", name: "run_terminal_command_v2", result: "https://github.com/org/repo/pull/1",
				params: `{"command":"gh pr create --title \"Bound the loader\" --body \"$(cat <<'EOB'\n## Summary\n- bound it\n\nMade with [Cursor](https://cursor.com)\nEOB\n)\""}`}.row(),
		},
		want: map[int][]string{1: {"commit", "pr"}},
	}, {
		// The containment path for bare-string records strips the attribution too, plain and escaped.
		name:  "a bare-string store with attribution still aligns",
		query: "commit and open a PR",
		transcript: jsonl(turn(use("Shell", `{"command":"git commit -m \"fix: bound the loader in the manifest reader\""}`)),
			turn(use("Shell", `{"command":"gh pr create --title \"Bound the loader\" --body \"## Summary\n- bound it\""}`))),
		bubbles: []storeRow{
			toolRow("commit", "run_terminal_command_v2", `git commit --trailer "Co-authored-by: Cursor <cursoragent@cursor.com>" -m "fix: bound the loader in the manifest reader"`, "1 file changed"),
			// A bare string holding JSON: the footer appears escaped.
			toolRow("pr", "run_terminal_command_v2", `captured {"command":"gh pr create --title \"Bound the loader\" --body \"## Summary\n- bound it\n\nMade with [Cursor](https://cursor.com)\""} (exit 0)`, "https://github.com/org/repo/pull/1"),
		},
		want: map[int][]string{1: {"commit"}, 2: {"pr"}},
	}, {
		// An errored call records only flags, and recording nothing contradicts nothing.
		name:       "an errored call recorded without arguments aligns",
		query:      "fix the table",
		transcript: turn(use("StrReplace", `{"file_path":"/work/api/AUDIT.md","old_string":"| batch B | open |","new_string":"| batch B | shipped |"}`)),
		bubbles: []storeRow{tool{id: "edit", name: "edit_file_v2", status: "error",
			params: `{"noCodeblock":true,"cloudAgentEdit":false}`, result: "the model produced an invalid edit"}.row()},
		want: map[int][]string{1: {"edit"}},
	}, {
		// The terminal params carry a parse tree of the command and the workspace root; a fragment of
		// it equal to the read's single value let the read steal the terminal bubble.
		name:  "the terminal parse tree cannot speak for another tool",
		query: "survey the repo",
		transcript: jsonl(turn(use("Read", `{"file_path":"render.yaml"}`)),
			turn(use("Shell", `{"command":"git show d63a490 -- render.yaml | head -30","description":"Inspect the pin commit"}`))),
		bubbles: []storeRow{
			tool{id: "shell", name: "run_terminal_command_v2", result: "render.yaml | 2 +-",
				params: `{"command":"git show d63a490 -- render.yaml | head -30","cwd":"","parsingResult":{"commands":[{"words":["git","show","d63a490","render.yaml","head"]}]},"requestedSandboxPolicy":{"workspace":"/work/api"},"commandDescription":"Inspect the pin commit"}`}.row(),
			toolRow("read", "read_file_v2", `{"path":"render.yaml"}`, "services:\n  - type: web"),
		},
		want: map[int][]string{1: {"read"}, 2: {"shell"}},
	}, {
		// One shared value among several is corroboration, not identity.
		name:       "a lone shared value among several is not identity",
		query:      "check the backends",
		transcript: jsonl(turn(use("Grep", `{"pattern":"StatusConflict|409","path":"/work/api"}`)), turn(use("Grep", `{"pattern":"PurgePrefix|VerifyCapabilities","path":"/work/api"}`))),
		bubbles: []storeRow{
			toolRow("purge", "ripgrep_raw_search", `{"pattern":"PurgePrefix|VerifyCapabilities","path":"/work/api"}`, "purge.go:14"),
			toolRow("conflict", "ripgrep_raw_search", `{"pattern":"StatusConflict|409","path":"/work/api"}`, "s3.go:88"),
		},
		want: map[int][]string{1: {"conflict"}, 2: {"purge"}},
	}})
}
