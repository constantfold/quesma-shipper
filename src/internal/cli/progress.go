package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

const (
	consoleLineBudget = 32
	plainEvery        = 100
	runLogName        = "last-sync.log"
	barCols           = 75
	barWidth          = 16
)

// progressStream shows the first per-file lines of a --once run, then a bar on a terminal or a
// periodic counter line elsewhere; every line also goes to the run log.
type progressStream struct {
	out     io.Writer // the console, always present: warnings go here even under --quiet
	log     io.Writer // nil until the log opens, and again if writing to it fails
	logFile *os.File
	logPath string
	quiet   bool
	tty     bool

	lines   int  // per-file lines already shown on the console
	noticed bool // whether the switch-over notice has been printed
	decided int
	sent    int
	errors  int

	frame string
}

func newProgressStream(out io.Writer, quiet bool) *progressStream {
	return &progressStream{out: out, quiet: quiet, tty: isTerminal(out)}
}

func (s *progressStream) openLog(stateDir string) {
	path := filepath.Join(stateDir, runLogName)
	var f *os.File
	err := platform.EnsureDir(stateDir, 0o700)
	if err == nil {
		f, err = platform.OpenTruncating(path, 0o600)
	}
	if err != nil {
		printWarning(s.Stderr(), "no run log this time: "+err.Error())
		return
	}
	s.logFile, s.log, s.logPath = f, f, path
}

func (s *progressStream) closeLog() {
	if s.logFile != nil {
		s.logFile.Close()
		s.logFile, s.log = nil, nil
	}
}

func (s *progressStream) emit(sourceID string, done, total int, f formats.FileOutcome) {
	line := progressLine(sourceID, done, total, f)
	if line != "" && s.log != nil {
		if _, err := fmt.Fprintln(s.log, line); err != nil {
			s.log = nil
			fmt.Fprintf(s.Stderr(), "warning: the run log stopped at %s: %v\n", s.logPath, err)
		}
	}
	s.decided++
	switch f.Decision {
	case formats.DecisionShipped:
		s.sent++
	case formats.DecisionParked, formats.DecisionFailed:
		s.errors++
	}
	switch {
	case s.quiet:
	case s.lines < consoleLineBudget:
		if line != "" {
			fmt.Fprintln(s.out, line)
			s.lines++
		}
	default:
		if line != "" && !s.noticed {
			s.noticed = true
			fmt.Fprintln(s.Stderr(), s.notice())
		}
		if s.tty {
			s.draw(progressFrame(sourceID, done, total, s.sent, s.errors, true))
		} else if s.decided%plainEvery == 0 {
			fmt.Fprintln(s.out, progressFrame(sourceID, done, total, s.sent, s.errors, false))
		}
	}
}

// Stderr is a writer that takes the bar down before a line and redraws it after.
func (s *progressStream) Stderr() io.Writer { return barWriter{s} }

func (s *progressStream) notice() string {
	where := "the summary below"
	if s.logPath != "" {
		where = s.logPath
	}
	return fmt.Sprintf("  … %d lines shown; the rest of this run is in %s", consoleLineBudget, where)
}

func (s *progressStream) draw(frame string) {
	pad := max(0, len(s.frame)-len(frame))
	fmt.Fprintf(s.out, "\r%s%s", frame, strings.Repeat(" ", pad))
	s.frame = frame
}

// Finish takes the bar down, leaving the cursor at the start of a blank line.
func (s *progressStream) Finish() {
	if s.frame != "" {
		fmt.Fprintf(s.out, "\r%s\r", strings.Repeat(" ", len(s.frame)))
		s.frame = ""
	}
}

type barWriter struct{ s *progressStream }

func (b barWriter) Write(p []byte) (int, error) {
	frame := b.s.frame
	b.s.Finish()
	n, err := b.s.out.Write(p)
	if frame != "" {
		b.s.draw(frame)
	}
	return n, err
}

// progressFrame is one transient progress line, the source id shortened so it never wraps past barCols.
func progressFrame(sourceID string, done, total, sent, errs int, bar bool) string {
	tail := fmt.Sprintf("  %d/%d  sent %d  errors %d", done, total, sent, errs)
	if bar {
		filled := 0
		if total > 0 {
			filled = min(done*barWidth/total, barWidth)
		}
		tail = "  [" + strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled) + "]" + tail
	}
	return sourceID[:min(len(sourceID), max(0, barCols-len(tail)))] + tail
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
