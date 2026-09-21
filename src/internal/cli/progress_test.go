package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// shipped is one decided file, the only outcome that produces a console line worth budgeting.
func shipped(n int) formats.FileOutcome {
	return formats.FileOutcome{
		SourceID: "claude-code-transcripts",
		RelPath:  fmt.Sprintf("projects/p/%03d.jsonl", n),
		Decision: formats.DecisionShipped,
		BytesIn:  1000,
		BytesOut: 400,
	}
}

// feed decides n files through the stream, as the loop would.
func feed(s *progressStream, n int, f func(int) formats.FileOutcome) {
	for i := 1; i <= n; i++ {
		s.emit("claude-code-transcripts", i, n, f(i))
	}
}

func TestTheConsoleStopsAfterTheBudgetAndSaysWhereTheRestWent(t *testing.T) {
	var console, log bytes.Buffer
	s := newProgressStream(&console, false)
	s.log, s.logPath = &log, "/state/last-sync.log"
	feed(s, consoleLineBudget+10, shipped)

	lines := strings.Split(strings.TrimRight(console.String(), "\n"), "\n")
	// The budget plus the notice: not a terminal, and the plain cadence has not come round.
	require.Len(t, lines, consoleLineBudget+1)
	notice := lines[len(lines)-1]
	assert.Containsf(t, notice, "/state/last-sync.log", "the notice does not name the log: %q", notice)
	assert.Containsf(t, notice, "32 lines shown", "the notice does not say what it cut: %q", notice)
	// Everything is in the log, including the lines the console dropped.
	assert.Equal(t, consoleLineBudget+10, strings.Count(log.String(), "\n"))
	assert.Containsf(t, log.String(), "042.jsonl", "a line past the console budget never reached the log:\n%s", log.String())
}

// The notice claims lines were cut, so it must not fire on a run that cut nothing.
func TestTheNoticeWaitsForALineTheConsoleActuallyDrops(t *testing.T) {
	var console, log bytes.Buffer
	s := newProgressStream(&console, false)
	s.log, s.logPath = &log, "/state/last-sync.log"
	s.tty = true

	feed(s, consoleLineBudget, shipped)
	require.NotContainsf(t, console.String(), "lines shown", "a run that showed every line sent the reader to the log:\n%s", console.String())

	s.emit("claude-code-transcripts", 33, 40, formats.FileOutcome{Decision: formats.DecisionUnchanged})
	assert.NotContainsf(t, console.String(), "lines shown", "an unchanged file, which prints nothing, triggered the notice:\n%s", console.String())

	s.emit("claude-code-transcripts", 34, 40, shipped(34))
	assert.Containsf(t, console.String(), "lines shown", "the first line the console dropped did not say where it went:\n%s", console.String())
}

// A pipe or a CI log gets a heartbeat instead of a bar: \r means nothing there.
func TestANonTerminalGetsAPlainLineEveryHundredFiles(t *testing.T) {
	var console bytes.Buffer
	s := newProgressStream(&console, false)
	feed(s, 250, shipped)

	out := console.String()
	assert.NotContainsf(t, out, "\r", "a non-terminal was sent carriage returns:\n%q", out)
	var plain []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "sent ") && !strings.HasPrefix(line, "[") {
			plain = append(plain, line)
		}
	}
	// 250 decided files past a 32-line budget: the cadence fires at 100 and 200.
	require.Lenf(t, plain, 2, "want two plain progress lines, got %d:\n%s", len(plain), out)
	assert.Containsf(t, plain[0], "100/250", "the first plain line is not at the hundredth file: %q", plain[0])
	assert.NotContainsf(t, plain[0], "[#", "a non-terminal was drawn a bar: %q", plain[0])
}

// A steady-state run prints nothing, so it must never reach the budget or draw a bar.
func TestUnchangedFilesAreSilentOnBothTheConsoleAndTheLog(t *testing.T) {
	var console, log bytes.Buffer
	s := newProgressStream(&console, false)
	s.log, s.logPath = &log, "/state/last-sync.log"
	s.tty = true
	feed(s, 500, func(int) formats.FileOutcome {
		return formats.FileOutcome{Decision: formats.DecisionUnchanged}
	})
	assert.Equal(t, 0, console.Len())
	assert.Equal(t, 0, log.Len())
}

func TestTheBarRewritesOneLineAndErasesWhatItShortens(t *testing.T) {
	var console bytes.Buffer
	s := newProgressStream(&console, false)
	s.tty = true
	feed(s, consoleLineBudget+3, shipped)

	tail := console.String()[strings.Index(console.String(), "\r"):]
	frames := strings.Split(tail, "\r")[1:]
	require.Lenf(t, frames, 3, "want one frame per file past the budget, got %d:\n%q", len(frames), tail)
	assert.NotContainsf(t, tail, "\n", "the bar started a new line instead of rewriting its own:\n%q", tail)
	for _, f := range frames {
		assert.Truef(t, len(f) <= barCols, "frame is %d columns, over the %d bound: %q", len(f), barCols, f)
	}

	// A shrinking frame must blank the columns the longer one left, or its tail stays on screen.
	s.draw("short")
	drawn := console.String()
	last := drawn[strings.LastIndex(drawn, "\r")+1:]
	assert.Truef(t, strings.HasPrefix(last, "short ") && strings.TrimSpace(last) == "short", "a shorter frame did not erase the longer one it replaced: %q", last)
}

func TestFinishTakesTheBarDown(t *testing.T) {
	var console bytes.Buffer
	s := newProgressStream(&console, false)
	s.tty = true
	feed(s, consoleLineBudget+1, shipped)
	before := console.Len()

	s.Finish()
	erased := console.String()[before:]
	assert.Equalf(t, "", strings.TrimSpace(strings.ReplaceAll(erased, "\r", "")), "Finish wrote something other than blanks: %q", erased)
	assert.Truef(t, strings.HasSuffix(erased, "\r"), "Finish left the cursor past the erased frame: %q", erased)
	// Idempotent: the summary printer does not have to know whether a bar was ever drawn.
	after := console.Len()
	s.Finish()
	assert.Equal(t, console.Len(), after)
}

// A mid-run warning needs the bar down before it and back up after it.
func TestAWarningOverTheBarGetsItsOwnLine(t *testing.T) {
	var console bytes.Buffer
	s := newProgressStream(&console, false)
	s.tty = true
	feed(s, consoleLineBudget+1, shipped)

	fmt.Fprintln(s.Stderr(), "warning: using the cached config")

	out := console.String()
	warn := strings.Index(out, "warning:")
	require.True(t, warn >= 0, "the warning never reached the console")
	before := out[:warn]
	if !strings.HasSuffix(before, "\r") {
		t.Errorf("the warning was written into the bar rather than over it: %q", before[len(before)-40:])
	}
	assert.Contains(t, out[warn:], "sent ", "the bar was not redrawn after the warning")
}

// --quiet drops console progress and the summary; the log is what an unattended run leaves.
func TestQuietStillWritesTheRunLog(t *testing.T) {
	var console, log bytes.Buffer
	s := newProgressStream(&console, true)
	s.log, s.logPath = &log, "/state/last-sync.log"
	feed(s, 5, shipped)

	assert.Equal(t, 0, console.Len())
	assert.Equal(t, 5, strings.Count(log.String(), "\n"))
}

// The e2e harness reads any counter word followed by a number as the run summary, so no
// transient rendering may contain one.
func TestTransientRenderingsCannotBeReadAsARunSummary(t *testing.T) {
	s := newProgressStream(&bytes.Buffer{}, false)
	s.logPath = "/state/last-sync.log"
	// Fed from the stream's own counters, the values emit passes at the real call sites.
	s.sent, s.errors = 396, 4
	renderings := []string{
		s.notice(),
		barFrame("claude-code-transcripts", 412, 1200, s.sent, s.errors),
		plainFrame("claude-code-transcripts", 412, 1200, s.sent, s.errors),
	}
	for _, r := range renderings {
		fields := strings.Fields(r)
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "shipped", "unchanged", "skipped", "parked", "failed":
				var n int
				if _, err := fmt.Sscanf(fields[i+1], "%d", &n); err == nil {
					t.Errorf("%q reads as a run summary at %q %q", r, fields[i], fields[i+1])
				}
			}
		}
	}
}

// A long source id must not push the frame past the bound: \r cannot erase a wrapped line.
func TestALongSourceIDIsShortenedRatherThanWrapped(t *testing.T) {
	frame := barFrame(strings.Repeat("s", 200), 5, 10, 5, 0)
	assert.Truef(t, len(frame) <= barCols, "frame is %d columns, over the %d bound: %q", len(frame), barCols, frame)
	assert.Containsf(t, frame, "5/10", "clamping ate the counters: %q", frame)
}

func TestIsTerminal(t *testing.T) {
	assert.True(t, !isTerminal(&bytes.Buffer{}), "a buffer is not a terminal")

	regular := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(regular)
	require.NoError(t, err)
	defer f.Close()
	assert.True(t, !isTerminal(f), "a regular file is not a terminal")

	// /dev/null is the known imprecision of a character-device check, and it is accepted.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("no %s here: %v", os.DevNull, err)
	}
	defer null.Close()
	if !isTerminal(null) {
		t.Errorf("%s is a character device; the check is meant to say so", os.DevNull)
	}
}
