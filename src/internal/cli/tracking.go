package cli

import (
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

func trackingCmd() *cobra.Command {
	cmd := verb("tracking", "What is collected, per agent and repository", browseTracking)
	cmd.Long = "What is collected, per agent and repository: size, what is still to be sent, when\n" +
		"it was last used. Press `t` on a repository to stop collecting from it (a `.notrajectories`\n" +
		"file is placed there, what was already sent stays sent) or to start again."
	return cmd
}

type key int

const (
	keyNone key = iota
	keyUp
	keyDown
	keyOpen
	keyBack
	keyToggle
	keyQuit
)

var keyBindings = map[string]key{
	"\x1b[A": keyUp, "\x1b[B": keyDown, "\x1b[C": keyOpen, "\x1b[D": keyBack,
	"k": keyUp, "j": keyDown, "\r": keyOpen, "\n": keyOpen, "l": keyOpen, "h": keyBack, "b": keyBack,
	"t": keyToggle, " ": keyToggle,
	"q": keyQuit, "\x03": keyQuit, "\x04": keyQuit, "\x1b": keyQuit, // q, Ctrl-C, Ctrl-D, Esc
}

// decodeKey reads an arrow from its escape sequence and any other key from its first byte.
func decodeKey(b []byte) key {
	if len(b) >= 3 && b[0] == 0x1b && b[1] == '[' {
		return keyBindings[string(b[:3])]
	}
	if len(b) == 0 {
		return keyNone
	}
	return keyBindings[string(b[:1])]
}

func browseTracking(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	view := &browser{pal: paletteFor(out)}
	if err := view.refresh(); err != nil {
		return err
	}
	stdin, ok := tty(cmd)
	if !ok {
		fmt.Fprint(out, view.screen(time.Now(), false))
		return nil
	}
	before := view.marked()
	if err := view.interact(stdin, out); err != nil {
		return err
	}
	fmt.Fprint(out, view.endNote(before))
	return nil
}

type browser struct {
	// attr outlives a refresh: its cwd cache is what keeps a toggle from re-probing every file.
	attr *sources.RepoFilter
	rows []app.AgentRow
	pal  palette

	open        string
	sel         int
	top         int
	height      int
	status      string
	statusStyle string
}

func (b *browser) refresh() error {
	was := ""
	if names := b.level(); b.sel < len(names) {
		was = names[b.sel]
	}
	eff, paths, err := app.ResolveEffective()
	if err != nil {
		return err
	}
	if b.attr == nil {
		b.attr = eff.Catalog.RepoFilter()
	}
	b.rows = app.Survey(eff, paths, b.attr)
	if b.agent() == nil {
		b.open = ""
	}
	b.sel = max(slices.Index(b.level(), was), 0)
	return nil
}

func (b *browser) level() []string {
	var names []string
	if a := b.agent(); a != nil {
		for _, r := range a.Repos {
			names = append(names, r.Dir)
		}
		return names
	}
	for _, a := range b.rows {
		names = append(names, a.Family)
	}
	return names
}

func (b *browser) agent() *app.AgentRow {
	if i := slices.IndexFunc(b.rows, func(a app.AgentRow) bool { return a.Family == b.open }); b.open != "" && i >= 0 {
		return &b.rows[i]
	}
	return nil
}

func (b *browser) clip(tbl string) string {
	lines := strings.Split(strings.TrimSuffix(tbl, "\n"), "\n")
	rows := lines[1:]
	avail := b.height - 4
	if b.status != "" {
		avail -= 2
	}
	if b.height == 0 || len(rows) <= avail {
		return tbl
	}
	fit := max(avail-2, 1)
	b.top = max(min(b.top, b.sel), b.sel-fit+1)
	b.top = max(min(b.top, len(rows)-fit), 0)

	out := lines[:1:1]
	if b.top > 0 {
		out = append(out, styled(b.pal.dim, fmt.Sprintf("   (%d more above)", b.top), b.pal.reset))
	}
	out = append(out, rows[b.top:b.top+fit]...)
	if below := len(rows) - b.top - fit; below > 0 {
		out = append(out, styled(b.pal.dim, fmt.Sprintf("   (%d more below)", below), b.pal.reset))
	}
	return strings.Join(out, "\n") + "\n"
}

func (b *browser) screen(now time.Time, raw bool) string {
	var body string
	if a := b.agent(); a != nil {
		body = renderRepos(*a, b.sel, now, b.pal)
	} else {
		body = renderAgents(b.rows, b.sel, now, b.pal)
	}
	body = b.clip(body)
	if b.status != "" {
		body += "\n" + styled(b.statusStyle, b.status, b.pal.reset) + "\n"
	}
	off := false
	if a := b.agent(); a != nil && b.sel < len(a.Repos) {
		off = a.Repos[b.sel].Off
	}
	body += "\n" + trackingHelp(b.pal, b.agent() != nil, off) + "\n"
	if raw {
		body = strings.ReplaceAll(body, "\n", "\r\n")
	}
	return body
}

func (b *browser) interact(stdin *os.File, out io.Writer) error {
	restore, err := term.MakeRaw(int(stdin.Fd()))
	if err != nil {
		fmt.Fprint(out, b.screen(time.Now(), false))
		return nil
	}
	fmt.Fprint(out, "\x1b[?1049h\x1b[?25l")
	defer func() {
		fmt.Fprint(out, "\x1b[?25h\x1b[?1049l")
		_ = term.Restore(int(stdin.Fd()), restore)
	}()

	buf := make([]byte, 8)
	for {
		if _, h, err := term.GetSize(int(stdin.Fd())); err == nil {
			b.height = h
		}
		fmt.Fprint(out, "\x1b[H\x1b[2J"+b.screen(time.Now(), true))
		k, ok := readKey(stdin, buf)
		if !ok {
			return nil
		}
		switch k {
		case keyQuit:
			return nil
		case keyUp:
			b.move(-1)
		case keyDown:
			b.move(1)
		case keyOpen:
			if b.agent() == nil && b.sel < len(b.rows) {
				b.open, b.sel, b.status = b.rows[b.sel].Family, 0, ""
			}
		case keyBack:
			if was := b.open; was != "" {
				b.open, b.status = "", ""
				b.sel = max(slices.Index(b.level(), was), 0)
			}
		case keyToggle:
			if err := b.toggle(); err != nil {
				return err
			}
			if err := b.refresh(); err != nil {
				return err
			}
		}
	}
}

func (b *browser) move(by int) {
	if n := len(b.level()); n > 0 {
		b.sel = (b.sel + by + n) % n
	}
}

func (b *browser) toggle() error {
	a := b.agent()
	if a == nil || b.sel >= len(a.Repos) {
		return nil
	}
	r := a.Repos[b.sel]
	if r.Dir == "" {
		b.status, b.statusStyle = "these sessions belong to no repository, so tracking cannot be switched off for them", b.pal.dim
		return nil
	}
	if !r.Off {
		b.status = ""
		return b.attr.Untrack(r.Dir)
	}
	own := sources.MarkerPath(r.Dir)
	if !slices.Contains(r.Markers, own) {
		b.status, b.statusStyle = "not tracked because of "+strings.Join(r.Markers, ", ")+", remove that file to track everything under it", b.pal.dim
		return nil
	}
	b.status = ""
	if others := slices.DeleteFunc(slices.Clone(r.Markers), func(m string) bool { return m == own }); len(others) > 0 {
		b.status, b.statusStyle = "some sessions stay untracked because of "+strings.Join(others, ", "), b.pal.dim
	}
	return b.attr.Track(r.Dir)
}

func (b *browser) endNote(before map[string]bool) string {
	after := b.marked()
	var lines []string
	for _, dir := range slices.Sorted(maps.Keys(after)) {
		was, now, name := before[dir], after[dir], sources.RepoName(dir)
		colour, change := b.pal.yellow, ": no longer tracked"
		if was {
			colour, change = b.pal.green, ": tracked again, everything not yet sent goes on the next run"
		}
		if was != now {
			lines = append(lines, "  "+styled(b.pal.bold, name, b.pal.reset)+styled(colour, change, b.pal.reset))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return styled(b.pal.dim, "tracking changes:", b.pal.reset) + "\n" + strings.Join(lines, "\n") + "\n"
}

func (b *browser) marked() map[string]bool {
	out := map[string]bool{}
	for _, a := range b.rows {
		for _, r := range a.Repos {
			if r.Dir != "" {
				out[r.Dir] = r.Off
			}
		}
	}
	return out
}
