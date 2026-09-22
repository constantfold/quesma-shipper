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
	return formats.FileOutcome{SourceID: "claude-code-transcripts", RelPath: fmt.Sprintf("projects/p/%03d.jsonl", n),
		Decision: formats.DecisionShipped, BytesIn: 1000, BytesOut: 400}
}

// newTestStream is a stream on console, with a run log in log when it is non-nil.
func newTestStream(console, log *bytes.Buffer, quiet, tty bool) *progressStream {
	s := newProgressStream(console, quiet)
	s.tty = tty
	if log != nil {
		s.log, s.logPath = log, "/state/last-sync.log"
	}
	return s
}

// feed decides n files through the stream, as the loop would.
func feed(s *progressStream, n int, f func(int) formats.FileOutcome) {
	for i := 1; i <= n; i++ {
		s.emit("claude-code-transcripts", i, n, f(i))
	}
}

func TestTheConsoleStopsAfterTheBudgetAndSaysWhereTheRestWent(t *testing.T) {
	var console, log bytes.Buffer
	s := newTestStream(&console, &log, false, false)
	feed(s, consoleLineBudget+10, shipped)

	lines := strings.Split(strings.TrimRight(console.String(), "\n"), "\n")
	// The budget plus the notice: not a terminal, and the plain cadence has not come round.
	require.Len(t, lines, consoleLineBudget+1)
	notice := lines[len(lines)-1]
	assert.Contains(t, notice, "/state/last-sync.log")
	assert.Contains(t, notice, "32 lines shown")
	// Everything is in the log, including the lines the console dropped.
	assert.Equal(t, consoleLineBudget+10, strings.Count(log.String(), "\n"))
	assert.Contains(t, log.String(), "042.jsonl")
}

// The notice claims lines were cut, so it must not fire on a run that cut nothing.
func TestTheNoticeWaitsForALineTheConsoleActuallyDrops(t *testing.T) {
	var console, log bytes.Buffer
	s := newTestStream(&console, &log, false, true)
	feed(s, consoleLineBudget, shipped)
	require.NotContains(t, console.String(), "lines shown", "a run that showed every line sent the reader to the log")
	s.emit("claude-code-transcripts", 33, 40, formats.FileOutcome{Decision: formats.DecisionUnchanged})
	assert.NotContains(t, console.String(), "lines shown", "an unchanged file, which prints nothing, triggered the notice")
	s.emit("claude-code-transcripts", 34, 40, shipped(34))
	assert.Contains(t, console.String(), "lines shown", "the first line the console dropped did not say where it went")
}

// A pipe or a CI log gets a heartbeat instead of a bar: \r means nothing there.
func TestANonTerminalGetsAPlainLineEveryHundredFiles(t *testing.T) {
	var console bytes.Buffer
	feed(newTestStream(&console, nil, false, false), 250, shipped)

	out := console.String()
	assert.NotContains(t, out, "\r")
	var plain []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "sent ") && !strings.HasPrefix(line, "[") {
			plain = append(plain, line)
		}
	}
	// 250 decided files past a 32-line budget: the cadence fires at 100 and 200.
	require.Len(t, plain, 2, out)
	assert.Contains(t, plain[0], "100/250")
	assert.NotContains(t, plain[0], "[#", "a non-terminal was drawn a bar")
}

// Unchanged files print nothing; --quiet drops console progress but still writes the run log.
func TestQuietRunsStillLog(t *testing.T) {
	var console, log bytes.Buffer
	feed(newTestStream(&console, &log, false, true), 500, func(int) formats.FileOutcome {
		return formats.FileOutcome{Decision: formats.DecisionUnchanged}
	})
	assert.Equal(t, 0, console.Len()+log.Len(), "unchanged files are silent on both the console and the log")

	feed(newTestStream(&console, &log, true, false), 5, shipped)
	assert.Equal(t, 0, console.Len())
	assert.Equal(t, 5, strings.Count(log.String(), "\n"))
}

func TestTheBar(t *testing.T) {
	var console bytes.Buffer
	s := newTestStream(&console, nil, false, true)
	feed(s, consoleLineBudget+3, shipped)

	tail := console.String()[strings.Index(console.String(), "\r"):]
	frames := strings.Split(tail, "\r")[1:]
	require.Len(t, frames, 3, "want one frame per file past the budget: %q", tail)
	assert.NotContains(t, tail, "\n", "the bar started a new line instead of rewriting its own")
	for _, f := range frames {
		assert.LessOrEqual(t, len(f), barCols, f)
	}

	// A mid-run warning takes the bar down before it and puts it back after it.
	fmt.Fprintln(s.Stderr(), "warning: using the cached config")
	out := console.String()
	warn := strings.Index(out, "warning:")
	assert.True(t, strings.HasSuffix(out[:warn], "\r"), "the warning was written into the bar rather than over it")
	assert.Contains(t, out[warn:], "sent ", "the bar was not redrawn after the warning")

	// A shrinking frame must blank the columns the longer one left, or its tail stays on screen.
	s.draw("short")
	drawn := console.String()
	last := drawn[strings.LastIndex(drawn, "\r")+1:]
	assert.True(t, strings.HasPrefix(last, "short ") && strings.TrimSpace(last) == "short", last)

	// Finish writes only blanks and leaves the cursor at the start, and a second one writes nothing.
	before := console.Len()
	s.Finish()
	erased := console.String()[before:]
	assert.Equal(t, "", strings.TrimSpace(strings.ReplaceAll(erased, "\r", "")))
	assert.True(t, strings.HasSuffix(erased, "\r"), erased)
	after := console.Len()
	s.Finish()
	assert.Equal(t, after, console.Len())
}

// The e2e harness reads a counter word and a number as the summary, so no transient line may hold one.
func TestTransientRenderings(t *testing.T) {
	s := newTestStream(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	for _, r := range []string{
		s.notice(),
		progressFrame("claude-code-transcripts", 412, 1200, 396, 4, true),
		progressFrame("claude-code-transcripts", 412, 1200, 396, 4, false),
	} {
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
	frame := progressFrame(strings.Repeat("s", 200), 5, 10, 5, 0, true)
	assert.LessOrEqual(t, len(frame), barCols, frame)
	assert.Contains(t, frame, "5/10", "clamping ate the counters")
}

func TestIsTerminal(t *testing.T) {
	assert.False(t, isTerminal(&bytes.Buffer{}))
	f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	require.NoError(t, err)
	defer f.Close()
	assert.False(t, isTerminal(f))
	// /dev/null is the known imprecision of a character-device check, and it is accepted.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("no %s here: %v", os.DevNull, err)
	}
	defer null.Close()
	assert.True(t, isTerminal(null))
}
