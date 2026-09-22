package cli

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/QuesmaOrg/quesma-shipper/app"
)

type palette struct {
	green, yellow, red, cyan, dim, bold, reset string
}

func ansiPalette() palette {
	return palette{green: "\x1b[32m", yellow: "\x1b[33m", red: "\x1b[31m", cyan: "\x1b[36m",
		dim: "\x1b[2m", bold: "\x1b[1m", reset: "\x1b[0m"}
}

var valueTokens = regexp.MustCompile(`[a-z][a-z0-9+.-]*://\S+` + // s3://…, https://…
	`|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+){2,}\b` + // host-likes: a.b.c
	`|\b\d{4}-\d{2}-\d{2}T\S+` + // RFC3339 timestamps
	`|\bv?\d+\.\d+[\w.+-]*` + // versions, 2.4s-style decimals
	`|\b\d+h(?:\d+m)?(?:\d+s)?\b|\b\d+m(?:\d+s)?\b|\b\d+s\b` + // durations
	`|\b\d[\d,]*\b`) // counts, with thousands separators

var backticked = regexp.MustCompile("`([^`]+)`")

func (p palette) names(s, restore string) string {
	return backticked.ReplaceAllStringFunc(s, func(tok string) string {
		return p.cyan + tok[1:len(tok)-1] + p.reset + restore
	})
}

func (p palette) paint(s, restore string) string {
	if p.cyan == "" {
		return s
	}
	return valueTokens.ReplaceAllStringFunc(s, func(tok string) string {
		return p.cyan + tok + p.reset + restore
	})
}

func colorEnabled(tty bool, getenv func(string) string) bool {
	return tty && getenv("NO_COLOR") == "" && getenv("TERM") != "dumb"
}

func paletteFor(w io.Writer) palette {
	if colorEnabled(isTerminal(w), os.Getenv) {
		return ansiPalette()
	}
	return palette{}
}

func (p palette) glyph(s app.Severity) string {
	switch s {
	case app.SevOK:
		return p.green + "✓" + p.reset
	case app.SevWarn:
		return p.yellow + "!" + p.reset
	case app.SevFail:
		return p.red + "✗" + p.reset
	default:
		return p.dim + "-" + p.reset
	}
}

// banner is the "<Title> <state>  (<why>)" line a verb ends on; an empty why drops the parenthetical.
func banner(w io.Writer, p palette, colour, state, why string) {
	line := styled(p.bold, app.Name, p.reset) + " " + styled(colour+p.bold, state, p.reset)
	if why != "" {
		line += "  " + styled(p.dim, "("+why+")", p.reset)
	}
	fmt.Fprintln(w, line)
}

const fixIndent = "     "

func renderSections(w io.Writer, p palette, secs []app.Section) {
	for i, sec := range secs {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if sec.Title != "" {
			fmt.Fprintf(w, "%s%s%s\n", p.dim, sec.Title, p.reset)
		}

		width := 0
		for _, row := range sec.Rows {
			if n := utf8.RuneCountInString(row.Head()); n > width && !row.Sub {
				width = n
			}
		}

		for _, row := range sec.Rows {
			style, reset, glyph := "", "", p.glyph(row.Sev)
			if row.Sev == app.SevDim {
				style, reset, glyph = p.dim, p.reset, "-"
			}
			var line string
			if row.Sub {
				detail := row.Detail
				if label := strings.TrimSpace(row.Label); label != "" {
					detail = label + ": " + detail
				}
				line = fixIndent + p.paint(detail, style)
			} else {
				label := row.Head()
				if row.Name {
					label = p.bold + row.Label + p.reset
					if row.Tag != "" {
						label += " " + p.cyan + row.Tag + p.reset
					}
				}
				label += strings.Repeat(" ", max(width-utf8.RuneCountInString(row.Head()), 0))
				line = strings.TrimRight(fmt.Sprintf("  %s  %s  %s", glyph, label, p.paint(row.Detail, style)), " ")
			}
			fmt.Fprintln(w, style+line+reset)
			for i, fix := range strings.Split(row.Fix, "\n") {
				if fix == "" {
					continue
				}
				lead := "→ "
				if i > 0 {
					lead = "  "
				}
				fmt.Fprintf(w, "%s%s%s%s%s\n", fixIndent, p.dim, lead, p.names(fix, p.dim), p.reset)
			}
		}
	}
}

func verdict(fails, warns int) string {
	if fails == 0 && warns == 0 {
		return "Everything is being collected."
	}
	problems, issues := "problems are", "issues need"
	if fails == 1 {
		problems = "problem is"
	}
	if warns == 1 {
		issues = "issue needs"
	}
	var parts []string
	if fails > 0 {
		parts = append(parts, fmt.Sprintf("%d %s stopping collection", fails, problems))
	}
	if warns > 0 {
		parts = append(parts, fmt.Sprintf("%d %s attention", warns, issues))
	}
	return strings.Join(parts, "; ") + "."
}

// printWarning indents a multi-line warning under its first line.
func printWarning(w io.Writer, warning string) {
	if warning != "" {
		fmt.Fprintf(w, "warning: %s\n", strings.ReplaceAll(warning, "\n", "\n         "))
	}
}
