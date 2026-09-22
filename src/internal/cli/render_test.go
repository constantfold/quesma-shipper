package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/QuesmaOrg/quesma-shipper/app"
)

func sectionsOutput(p palette, secs ...app.Section) string {
	var out bytes.Buffer
	renderSections(&out, p, secs)
	return out.String()
}

// Columns align by rune count, not bytes, so a multi-byte label cannot shift them.
func TestRenderSectionsLayout(t *testing.T) {
	assert.Equal(t, "Check\n"+
		"  ✓  a       first\n"+
		"  !  länger  second\n"+
		"     → do the thing\n"+
		"  -  b       third\n",
		sectionsOutput(palette{}, app.Section{Title: "Check", Rows: []app.Row{
			{Sev: app.SevOK, Label: "a", Detail: "first"},
			{Sev: app.SevWarn, Label: "länger", Detail: "second", Fix: "do the thing"}, // 6 runes, 7 bytes
			{Sev: app.SevDim, Label: "b", Detail: "third"},
		}}))
	assert.Equal(t, "  !  parked  2 file(s)\n     → one\n       two\n",
		sectionsOutput(palette{}, app.Section{Rows: []app.Row{{Sev: app.SevWarn, Label: "parked", Detail: "2 file(s)", Fix: "one\ntwo"}}}))

	s := sectionsOutput(ansiPalette(), app.Section{Title: "T", Rows: []app.Row{
		{Sev: app.SevOK, Label: "fine", Detail: "yes"},
		{Sev: app.SevDim, Label: "ref", Detail: "detail"},
	}})
	for _, want := range []string{"\x1b[32m✓\x1b[0m", "\x1b[2mT\x1b[0m", "\x1b[2m  -  ref"} { // green glyph, dim title, dim row
		assert.Contains(t, s, want)
	}
}

// Which substrings read as values, and that a dim row restores its dim.
func TestPaint(t *testing.T) {
	p := ansiPalette()
	for _, c := range []struct {
		in             string
		painted, plain []string
	}{
		{"1,021 sessions across 30 projects", []string{"1,021", "30"}, []string{"sessions", "projects"}},
		{"s3://bucket/path - write access verified", []string{"s3://bucket/path"}, []string{"write"}},
		{"quesma · control.example.com - connected", []string{"control.example.com"}, []string{"connected"}},
		{"v0.144.6 and 0.0.0-95c699c34d8b+dirty", []string{"v0.144.6"}, nil},
		{"9m30s ago, checked 2.4s", []string{"9m30s", "2.4s"}, []string{"ago"}},
		{"fetched 2026-08-18T16:31:52+02:00", []string{"2026-08-18T16:31:52+02:00"}, nil},
	} {
		got := p.paint(c.in, "")
		for _, tok := range c.painted {
			assert.Contains(t, got, p.cyan+tok+p.reset)
		}
		for _, word := range c.plain {
			assert.NotContains(t, got, p.cyan+word)
		}
	}
	assert.Contains(t, p.paint("12 files", p.dim), p.cyan+"12"+p.reset+p.dim)
	assert.Equal(t, "12 files", (palette{}).paint("12 files", ""))
}

func TestColorEnabled(t *testing.T) {
	for _, c := range []struct {
		tty  bool
		env  map[string]string
		want bool
	}{
		{false, nil, false},
		{true, nil, true},
		{true, map[string]string{"NO_COLOR": "1"}, false},
		{true, map[string]string{"TERM": "dumb"}, false},
	} {
		assert.Equal(t, c.want, colorEnabled(c.tty, func(k string) string { return c.env[k] }), "%v", c)
	}
}

func TestVerdict(t *testing.T) {
	for in, want := range map[[2]int]string{
		{0, 0}: "Everything is being collected.",
		{0, 1}: "1 issue needs attention.",
		{0, 3}: "3 issues need attention.",
		{1, 0}: "1 problem is stopping collection.",
		{2, 2}: "2 problems are stopping collection; 2 issues need attention.",
		{1, 1}: "1 problem is stopping collection; 1 issue needs attention.",
	} {
		assert.Equal(t, want, verdict(in[0], in[1]))
	}
}
