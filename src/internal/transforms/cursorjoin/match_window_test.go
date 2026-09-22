package cursorjoin_test

import (
	"fmt"
	"testing"
)

// Where the matcher looks: behind the cursor for out-of-order bubbles, never past the forward window.
func TestMatchWindows(t *testing.T) {
	var far []storeRow
	for i := range 20 {
		far = append(far, toolRow(fmt.Sprintf("fill%02d", i), "read_file_v2", fmt.Sprintf(`{"path":"/work/api/f%02d.go"}`, i), "unrelated"))
	}
	// Twenty unrelated calls put a tempting match beyond the forward window.
	beyondWindow := func(name, input, distantArgs string) joinCase {
		return joinCase{
			name:       name,
			query:      "find the deny rules",
			transcript: turn(use("Grep", input)),
			bubbles: append(append([]storeRow{toolRow("near", "ripgrep_raw_search", `{}`, "the right result")}, far...),
				toolRow("far", "ripgrep_raw_search", distantArgs, "the WRONG result")),
			want: map[int][]string{1: {"near"}},
		}
	}
	const read = `{"path":"/work/api/internal/config/resolve.go"}`
	runJoinCases(t, []joinCase{
		beyondWindow("substring coincidence stays out of reach", `{"pattern":"deny","glob":"**/*","output_mode":"files_with_matches"}`,
			`{"pattern":"signed","glob":"**/*.{md,json,yaml,go}"}`),
		beyondWindow("identical arguments stay out of reach", `{"pattern":"deny_additions","path":"/work/api/internal/config"}`,
			`{"pattern":"deny_additions","path":"/work/api/internal/config"}`),
		{
			// The store puts the task before the prose, so the prose match advances the cursor past it.
			name:       "an out-of-order tool bubble is found behind the cursor",
			query:      "check types",
			transcript: turn(text("Spawning a typecheck subagent."), use("Task", `{"description":"Typecheck the repo","prompt":"Run npx tsc --noEmit in the repo and report errors."}`)),
			bubbles: []storeRow{
				tool{id: "task1", name: "task_v2", result: "no type errors",
					params: `{"description":"Typecheck the repo","prompt":"Run npx tsc --noEmit in the repo and report errors."}`}.row(),
				said("a1", "Spawning a typecheck subagent."),
			},
			want: map[int][]string{1: {"a1", "task1"}},
		}, {
			// An argument-less call never grades positive: the nearest name-compatible bubble is the last resort.
			name:       "a terminal bubble left behind the cursor is still found",
			query:      "what changed",
			transcript: turn(use("Read", read), use("Shell", `{"command":"git status --short"}`)),
			bubbles: []storeRow{
				toolRow("shell", "run_terminal_command_v2", `{}`, " M internal/config/resolve.go"),
				toolRow("read", "read_file_v2", read, "package config"),
			},
			want: map[int][]string{1: {"read", "shell"}},
		}, {
			// Nothing but position separates two argument-less siblings: the nearest wins.
			name:       "the positional look-behind takes the nearest sibling",
			query:      "what changed",
			transcript: turn(use("Read", read), use("Shell", `{"command":"git status --short"}`)),
			bubbles: []storeRow{
				toolRow("shellFar", "run_terminal_command_v2", `{}`, "the FAR sibling"),
				toolRow("shellNear", "run_terminal_command_v2", `{}`, " M internal/config/resolve.go"),
				toolRow("read", "read_file_v2", read, "package config"),
			},
			want: map[int][]string{1: {"read", "shellNear"}},
		}, {
			// Prose gets no positional look-behind: an empty block would otherwise take anything.
			name:       "a text block does not claim a passed-over bubble on position alone",
			query:      "what changed",
			transcript: turn(use("Read", read), text("")),
			bubbles:    []storeRow{said("prose", "Reading the resolver first."), toolRow("read", "read_file_v2", read, "package config")},
			want:       map[int][]string{1: {"read", ""}},
		},
	})
}
