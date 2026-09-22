package cli

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QuesmaOrg/quesma-shipper/app"
)

func table(heads []string, right []bool, nameCol int, rows [][]string, rowStyle []string, pal palette) string {
	width := make([]int, len(heads))
	measure := func(cells []string) {
		for i, cell := range cells {
			width[i] = max(width[i], utf8.RuneCountInString(cell))
		}
	}
	measure(heads)
	for _, row := range rows {
		measure(row)
	}
	line := func(cells []string, style string, paint bool) string {
		var b strings.Builder
		b.WriteString(style)
		for i, cell := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			pad := strings.Repeat(" ", width[i]-utf8.RuneCountInString(cell))
			text := cell + pad
			if right[i] {
				text = pad + cell
			}
			switch {
			case !paint || strings.TrimSpace(cell) == "":
			case i == 0 || i == nameCol:
				text = styled(pal.bold, text, pal.reset+style)
			default:
				text = paintValue(text, pal, style)
			}
			b.WriteString(text)
		}
		out := strings.TrimRight(b.String(), " ")
		if style != "" {
			return strings.TrimSuffix(out, style) + pal.reset
		}
		return out
	}
	var b strings.Builder
	b.WriteString(line(heads, pal.dim, false) + "\n")
	for i, row := range rows {
		b.WriteString(line(row, rowStyle[i], true) + "\n")
	}
	return b.String()
}

var leadingNumber = regexp.MustCompile(`^(\s*)(\d[\d,.]*)`)

func paintValue(cell string, pal palette, restore string) string {
	if strings.TrimSpace(cell) == "n/a" {
		return styled(pal.dim, cell, pal.reset+restore)
	}
	return leadingNumber.ReplaceAllString(cell, "$1"+pal.cyan+"$2"+pal.reset+restore)
}

func rowStyle(pal palette, selected, off bool) string {
	switch {
	case off:
		return pal.dim
	case selected:
		return pal.bold
	}
	return ""
}

func renderAgents(rows []app.AgentRow, sel int, now time.Time, pal palette) string {
	cells := make([][]string, len(rows))
	styles := make([]string, len(rows))
	for i, a := range rows {
		state, repos, size, pending, last := "", "", "", "", ""
		if len(a.Repos) == 0 {
			state = "not installed"
		} else {
			repos, size, last = strconv.Itoa(len(a.Repos)), bytesCell(a.Bytes), app.Ago(a.Last, now)
			pending = toSync(a.Pending, a.PendingKnown)
		}
		cells[i] = []string{cursor(i == sel), a.Display, repos, size, pending, last, state}
		styles[i] = rowStyle(pal, i == sel, len(a.Repos) == 0)
	}
	return table([]string{" ", "agent", "repos", "size", "to send", "last used", ""},
		[]bool{false, false, true, true, true, false, false}, 1, cells, styles, pal)
}

func renderRepos(a app.AgentRow, sel int, now time.Time, pal palette) string {
	cells := make([][]string, len(a.Repos))
	styles := make([]string, len(a.Repos))
	for i, r := range a.Repos {
		state, pending := "", "n/a"
		if r.Off {
			state = "not tracked"
		} else {
			pending = toSync(r.Pending, a.PendingKnown)
		}
		cells[i] = []string{cursor(i == sel), cmp.Or(r.Name, "(no repository found)"),
			bytesCell(r.Bytes), pending, app.Ago(r.Last, now), state}
		styles[i] = rowStyle(pal, i == sel, r.Off)
	}
	return table([]string{" ", strings.ToLower(a.Display), "size", "to send", "last used", ""},
		[]bool{false, false, true, true, false, false}, 1, cells, styles, pal)
}

func cursor(on bool) string {
	if on {
		return ">"
	}
	return " "
}

func toSync(n int64, known bool) string {
	if !known {
		return "n/a"
	}
	return bytesCell(n)
}

func bytesCell(n int64) string {
	if n == 0 {
		return "0 MB"
	}
	return app.HumanBytes(n)
}

func trackingHelp(pal palette, repoLevel, off bool) string {
	toggle := "stop tracking  "
	if off {
		toggle = "resume tracking"
	}
	if !repoLevel {
		return keyHelp(pal, [][2]string{{"↑↓", "move"}, {"enter", "open"}, {"q", "quit"}})
	}
	return keyHelp(pal, [][2]string{{"↑↓", "move"}, {"enter", "open"}, {"t", toggle}, {"b", "back"}, {"q", "quit"}})
}

// keyHelp is the footer naming each key and what it does.
func keyHelp(pal palette, keys [][2]string) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, styled(pal.cyan, k[0], pal.reset)+styled(pal.dim, " "+k[1], pal.reset))
	}
	return strings.Join(parts, "  ")
}

func styled(style, s, reset string) string {
	if style == "" {
		return s
	}
	return style + s + reset
}
