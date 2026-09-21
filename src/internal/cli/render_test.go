package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
)

// Columns align by rune count, not bytes, so a multi-byte label cannot shift them.
func TestRenderSectionsAlignment(t *testing.T) {
	var out bytes.Buffer
	renderSections(&out, palette{}, []app.Section{{
		Title: "Check",
		Rows: []app.Row{
			{Sev: app.SevOK, Label: "a", Detail: "first"},
			// 6 runes but 7 bytes: byte-counted padding would misalign every row after it.
			{Sev: app.SevWarn, Label: "länger", Detail: "second", Fix: "do the thing"},
			{Sev: app.SevDim, Label: "b", Detail: "third"},
		},
	}})

	want := "" +
		"Check\n" +
		"  ✓  a       first\n" +
		"  !  länger  second\n" +
		"     → do the thing\n" +
		"  -  b       third\n"
	require.Equalf(t, want, out.String(), "layout drifted:\ngot:\n%q\nwant:\n%q", out.String(), want)
}

func TestRenderSectionsUntitledAndMultilineFix(t *testing.T) {
	var out bytes.Buffer
	renderSections(&out, palette{}, []app.Section{{
		Rows: []app.Row{{Sev: app.SevWarn, Label: "parked", Detail: "2 file(s)", Fix: "one\ntwo"}},
	}})
	want := "" +
		"  !  parked  2 file(s)\n" +
		"     → one\n" +
		"       two\n"
	require.Equalf(t, want, out.String(), "got:\n%q\nwant:\n%q", out.String(), want)
}

func TestRenderSectionsColor(t *testing.T) {
	var out bytes.Buffer
	renderSections(&out, ansiPalette(), []app.Section{{
		Title: "T",
		Rows: []app.Row{
			{Sev: app.SevOK, Label: "fine", Detail: "yes"},
			{Sev: app.SevDim, Label: "ref", Detail: "detail"},
		},
	}})
	s := out.String()
	for _, want := range []string{
		"\x1b[32m✓\x1b[0m", // green glyph
		"\x1b[2mT\x1b[0m",  // dim title
		"\x1b[2m  -  ref",  // dim rows dim as a whole line
	} {
		assert.Containsf(t, s, want, "missing %q in:\n%q", want, s)
	}
}

// TestPaint pins which substrings read as values, and that a dim row restores its dim.
func TestPaint(t *testing.T) {
	p := ansiPalette()
	cases := []struct {
		in   string
		want []string // painted tokens
		not  []string // must stay unpainted
	}{
		{"1,021 sessions across 30 projects", []string{"1,021", "30"}, []string{"sessions", "projects"}},
		{"s3://bucket/path - write access verified", []string{"s3://bucket/path"}, []string{"write"}},
		{"quesma · control.example.com - connected", []string{"control.example.com"}, []string{"connected"}},
		{"v0.144.6 and 0.0.0-95c699c34d8b+dirty", []string{"v0.144.6"}, nil},
		{"9m30s ago, checked 2.4s", []string{"9m30s", "2.4s"}, []string{"ago"}},
		{"fetched 2026-08-18T16:31:52+02:00", []string{"2026-08-18T16:31:52+02:00"}, nil},
	}
	for _, c := range cases {
		got := p.paint(c.in, "")
		for _, tok := range c.want {
			assert.Contains(t, got, p.cyan+tok+p.reset)
		}
		for _, word := range c.not {
			assert.NotContains(t, got, p.cyan+word)
		}
	}

	assert.Contains(t, p.paint("12 files", p.dim), p.cyan+"12"+p.reset+p.dim)
	assert.Equal(t, "12 files", (palette{}).paint("12 files", ""))
}

func TestColorEnabled(t *testing.T) {
	env := func(vals map[string]string) func(string) string {
		return func(k string) string { return vals[k] }
	}
	cases := []struct {
		name string
		tty  bool
		vals map[string]string
		want bool
	}{
		{"piped", false, nil, false},
		{"tty", true, nil, true},
		{"no_color", true, map[string]string{"NO_COLOR": "1"}, false},
		{"dumb_term", true, map[string]string{"TERM": "dumb"}, false},
	}
	for _, c := range cases {
		assert.Equal(t, colorEnabled(c.tty, env(c.vals)), c.want)
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		fails, warns int
		want         string
	}{
		{0, 0, "Everything is being collected."},
		{0, 1, "1 issue needs attention."},
		{0, 3, "3 issues need attention."},
		{1, 0, "1 problem is stopping collection."},
		{2, 2, "2 problems are stopping collection; 2 issues need attention."},
	}
	for _, c := range cases {
		assert.Equal(t, verdict(c.fails, c.warns), c.want)
	}
}
