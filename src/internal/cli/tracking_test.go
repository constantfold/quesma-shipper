package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

var testNow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func TestDecodeKey(t *testing.T) {
	for in, want := range map[string]key{
		"\x1b[A": keyUp, "\x1b[B": keyDown, "\x1b[C": keyOpen, "\x1b[D": keyBack,
		"k": keyUp, "j": keyDown, "\r": keyOpen, "b": keyBack, "t": keyToggle, " ": keyToggle, "q": keyQuit, "\x03": keyQuit,
		"z": keyNone, "\x1b[Z": keyNone, "": keyNone,
	} {
		assert.Equal(t, want, decodeKey([]byte(in)), "%q", in)
	}
}

func TestCursorWrapsAndSurvivesAnEmptyLevel(t *testing.T) {
	b := &browser{rows: browseRows(t.TempDir())}
	b.move(-1)
	assert.Equal(t, 1, b.sel, "up from the first row wraps")
	b.move(1)
	assert.Equal(t, 0, b.sel, "down from the last row wraps")
	empty := &browser{}
	empty.move(1)
	assert.Equal(t, 0, empty.sel)
}

func TestScreenFrames(t *testing.T) {
	b := &browser{rows: browseRows(t.TempDir()), status: "something happened"}
	assert.NotContains(t, strings.ReplaceAll(b.screen(testNow, true), "\r\n", ""), "\n")
	plain := b.screen(testNow, false)
	assert.NotContains(t, plain, "\r")
	assert.Contains(t, plain, "something happened")
	assert.Contains(t, plain, trackingHelp(palette{}, false, false))
}

func TestClipKeepsTheHeaderAndTheCursorVisible(t *testing.T) {
	repos := make([]app.RepoRow, 30)
	for i := range repos {
		repos[i] = app.RepoRow{Name: fmt.Sprintf("repo-%02d", i)}
	}
	b := &browser{rows: []app.AgentRow{{Family: "claude-code", Display: "Claude Code", Repos: repos}}, open: "claude-code", height: 12}

	lines := strings.Split(strings.TrimSuffix(b.screen(testNow, false), "\n"), "\n")
	require.LessOrEqual(t, len(lines), b.height-1)
	assert.Contains(t, lines[0], "claude code", "header not pinned")
	frame := strings.Join(lines, "\n")
	assert.True(t, strings.Contains(frame, ">  repo-00") && strings.Contains(frame, "(24 more below)"), "first page:\n%s", frame)

	b.sel = 29
	frame = b.screen(testNow, false)
	assert.True(t, strings.Contains(frame, ">  repo-29") && strings.Contains(frame, "(24 more above)"), "last page:\n%s", frame)

	b.sel, b.open = 0, ""
	assert.Contains(t, b.screen(testNow, false), ">  Claude Code", "a stale offset survived the level change")

	b.height, b.open, b.sel = 0, "claude-code", 15
	frame = b.screen(testNow, false)
	assert.True(t, !strings.Contains(frame, "more") && strings.Contains(frame, "repo-29"), "without a height every row shows:\n%s", frame)
}

func TestAgentRows(t *testing.T) {
	used := func(daysAgo int, size int64) sources.Candidate {
		return sources.Candidate{MTime: testNow.AddDate(0, 0, -daysAgo), Size: size}
	}
	sorted := &app.AgentRow{}
	sorted.Add("/w/old-big", used(3, 500), "", false)
	sorted.Add("/w/today-small", used(0, 1), "", false)
	sorted.Add("/w/today-big", used(0, 100), "", false)
	app.SortRepos(sorted.Repos)
	var names []string
	for _, r := range sorted.Repos {
		names = append(names, r.Name)
	}
	assert.Equal(t, []string{"today-big", "today-small", "old-big"}, names, "repos sort by day, then size")

	var a app.AgentRow
	a.Add("/w/acme", sources.Candidate{Size: 100, MTime: testNow}, "", false)
	a.Add("/w/acme", sources.Candidate{Size: 200, MTime: testNow.Add(time.Hour)}, "", true)
	a.Add("", sources.Candidate{Size: 50, MTime: testNow.Add(-time.Hour)}, "", true)
	assert.True(t, a.Bytes == 350 && a.Pending == 250 && a.Last.Equal(testNow.Add(time.Hour)), "totals = %+v", a)
	assert.True(t, len(a.Repos) == 2 && a.Repos[0].Name == "acme" && a.Repos[0].Bytes == 300 && a.Repos[0].Pending == 200 && a.Repos[1].Name == "", "repos = %+v", a.Repos)
}

func TestAgoAndBytes(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second: "just now", 20 * time.Minute: "20 min ago", 5 * time.Hour: "5 hours ago",
		30 * time.Hour: "1 day ago", 20 * 24 * time.Hour: "20 days ago", 400 * 24 * time.Hour: "13 months ago",
	} {
		assert.Equal(t, want, app.Ago(testNow.Add(-d), testNow))
	}
	for in, want := range map[int64]string{0: "0 MB", 1: "1 B", 512: "512 B", 465_000: "454.1 KB", 1<<20 - 1: "1024.0 KB", 12_165_120: "11.6 MB", 1667 << 20: "1667.0 MB"} {
		assert.Equal(t, want, bytesCell(in))
	}
	assert.True(t, toSync(0, true) == "0 MB" && toSync(0, false) == "n/a", "nothing to send is 0 MB, unknown is n/a")
}

func renderRows() []app.AgentRow {
	return []app.AgentRow{
		{Family: "claude-code", Display: "Claude Code", Bytes: 1747 << 20, Pending: 40 << 20, PendingKnown: true, Last: testNow.Add(-time.Minute),
			Repos: []app.RepoRow{
				{Name: "keeper", Bytes: 100 << 20, Pending: 40 << 20, Last: testNow.Add(-2 * time.Hour)},
				{Name: "client-acme", Bytes: 48 << 20, Last: testNow.Add(-72 * time.Hour), Off: true},
				{Name: "", Bytes: 1 << 10, Last: testNow.Add(-time.Hour)},
			}},
		{Family: "cursor", Display: "Cursor"},
		{Family: "codex", Display: "Codex"},
	}
}

func TestPlainRendering(t *testing.T) {
	rows := renderRows()
	agents := renderAgents(rows, 0, testNow, palette{})
	repos := renderRepos(rows[0], 1, testNow, palette{})
	for _, want := range []string{"Cursor", "not installed", "1747.0 MB", "40.0 MB"} {
		assert.Contains(t, agents, want)
	}
	for _, want := range []string{"client-acme", "not tracked", "(no repository found)", "100.0 MB", "48.0 MB"} {
		assert.Contains(t, repos, want)
	}
	lines := strings.Split(strings.TrimRight(repos, "\n"), "\n")
	assert.Equal(t, strings.Index(lines[2], "48.0 MB")+7, strings.Index(lines[1], "100.0 MB")+8, "sizes do not share a right edge:\n%s", repos)
	assert.True(t, strings.Contains(lines[2], "n/a") && strings.Count(strings.Fields(lines[2])[0], ">") == 1, "an excluded row must not claim an empty queue, and one row carries the cursor:\n%s", repos)
	for _, line := range append(lines, strings.Split(agents, "\n")...) {
		assert.True(t, line == strings.TrimRight(line, " ") && !strings.Contains(line, "\x1b"), "padding or escapes in a plain line: %q", line)
	}
}

var ansiSeq = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Stripped of escapes, the painted table is the plain one byte for byte.
func TestColourRendering(t *testing.T) {
	pal := ansiPalette()
	rows := renderRows()
	for _, pair := range [][2]string{
		{renderAgents(rows, 0, testNow, pal), renderAgents(rows, 0, testNow, palette{})},
		{renderRepos(rows[0], 0, testNow, pal), renderRepos(rows[0], 0, testNow, palette{})},
		{trackingHelp(pal, true, false), trackingHelp(palette{}, true, false)},
	} {
		assert.Equal(t, pair[1], ansiSeq.ReplaceAllString(pair[0], ""))
	}
	lines := strings.Split(strings.TrimRight(renderAgents(rows, 1, testNow, pal), "\n"), "\n")
	assert.True(t, strings.HasPrefix(lines[0], pal.dim) && !strings.HasPrefix(lines[1], pal.dim) && strings.HasPrefix(lines[3], pal.dim), "header dim, collected row plain, absent row dim:\n%q", lines)
	assert.True(t, strings.HasPrefix(lines[2], pal.dim) && strings.Contains(lines[2], pal.bold+">"), "the selected excluded row keeps its dim and shows the cursor: %q", lines[2])
	assert.True(t, strings.Contains(lines[1], "    "+pal.cyan+"3"+pal.reset) && strings.Contains(lines[1], pal.cyan+"1747.0"+pal.reset+" MB") && !strings.Contains(lines[3], pal.cyan+" "),
		"numbers cyan, units plain, blanks unpainted: %q / %q", lines[1], lines[3])
	assert.Contains(t, trackingHelp(pal, true, false), pal.cyan+"t"+pal.reset, "keys are painted")
	on, off := trackingHelp(palette{}, true, false), trackingHelp(palette{}, true, true)
	assert.True(t, strings.Contains(on, "stop tracking") && strings.Contains(off, "resume tracking") && len(on) == len(off), "the t key names what it will do, at one width: %q / %q", on, off)
	assert.NotContains(t, trackingHelp(pal, false, false), "tracking", "the agent level offers no toggle")
}

// browseRows is a survey over dir, optionally with client-acme under markers.
func browseRows(dir string, markers ...string) []app.AgentRow {
	return []app.AgentRow{
		{Family: "claude-code", Display: "Claude Code", Repos: []app.RepoRow{
			{Name: "keeper", Dir: filepath.Join(dir, "keeper")},
			{Name: "client-acme", Dir: filepath.Join(dir, "client-acme"), Off: len(markers) > 0, Markers: markers},
			{Name: ""},
		}},
		{Family: "cursor", Display: "Cursor"},
	}
}

func TestToggle(t *testing.T) {
	home := t.TempDir()
	acme := filepath.Join(home, "client-acme")
	require.NoError(t, os.MkdirAll(filepath.Join(home, "keeper"), 0o700))
	require.NoError(t, os.MkdirAll(acme, 0o700))
	catalog, err := sources.Load()
	require.NoError(t, err)
	attr := catalog.RepoFilter()
	pal := ansiPalette()
	own, above := sources.MarkerPath(acme), sources.MarkerPath(home)
	worktree := sources.MarkerPath(filepath.Join(home, "wt", "stray"))
	marked := func() bool { _, ok := attr.Marker(acme); return ok }
	// toggle presses t on row sel of level open and returns the status line it leaves.
	toggle := func(rows []app.AgentRow, open string, sel int) string {
		t.Helper()
		b := &browser{rows: rows, attr: attr, pal: pal, open: open, sel: sel}
		require.NoError(t, b.toggle())
		return b.status
	}

	assert.Empty(t, toggle(browseRows(home), "claude-code", 1), "a successful toggle says nothing")
	require.True(t, marked(), "the marker was not written")
	assert.Empty(t, toggle(browseRows(home, own), "claude-code", 1))
	require.False(t, marked(), "the marker was not removed")
	assert.Contains(t, toggle(browseRows(home, above), "claude-code", 1), above, "an ancestor marker is named")
	require.NoError(t, attr.Untrack(acme))
	msg := toggle(browseRows(home, worktree, own), "claude-code", 1)
	assert.True(t, strings.Contains(msg, worktree) && !strings.Contains(msg, own), "the remaining worktree marker is named: %q", msg)
	require.False(t, marked(), "the repository's own marker was not removed")
	assert.Contains(t, toggle(browseRows(home), "claude-code", 2), "no repository", "unattributed sessions cannot be marked")
	assert.Empty(t, toggle(browseRows(home), "", 1), "the agent level has nothing to toggle")
}

func TestEndNoteSaysTheNetChange(t *testing.T) {
	pal := ansiPalette()
	home := t.TempDir()
	keeper, acme := filepath.Join(home, "keeper"), filepath.Join(home, "client-acme")
	b := &browser{pal: pal, rows: browseRows(home, sources.MarkerPath(acme))}

	note := b.endNote(map[string]bool{keeper: false, acme: false})
	assert.True(t, strings.HasPrefix(note, styled(pal.dim, "tracking changes:", pal.reset)), note)
	assert.Contains(t, note, "  "+styled(pal.bold, "client-acme", pal.reset)+styled(pal.yellow, ": no longer tracked", pal.reset))
	assert.NotContains(t, note, "keeper", "an unchanged repository has no bullet")
	assert.Equal(t, "", b.endNote(b.marked()))
	assert.Contains(t, b.endNote(map[string]bool{keeper: true, acme: true}), "tracked again, everything not yet sent goes on the next run")
}
