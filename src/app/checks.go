package app

import (
	"cmp"
	"strings"
)

type Severity int

const (
	SevDim Severity = iota
	SevOK
	SevWarn
	SevFail
)

type Row struct {
	Sev                            Severity
	Label, Detail, Fix, Brief, Tag string
	Rollup, Sub, Name              bool
}

func (r Row) Head() string {
	if r.Tag == "" {
		return r.Label
	}
	return r.Label + " " + r.Tag
}

func Plain(s string) string { return strings.ReplaceAll(s, "`", "") }

type Section struct {
	Title string
	Rows  []Row
}

type Report struct {
	Sections                     []Section
	Update                       UpdateStatus
	Organization, Endpoint       string
	AgentsCollecting, FilesFound int
}

func (r *Report) Issues() (out []string, fails int) {
	for _, sec := range r.Sections {
		for _, row := range sec.Rows {
			if row.Sev == SevFail {
				fails++
			}
			if row.Sev == SevFail || (row.Sev == SevWarn && !row.Rollup) {
				out = append(out, cmp.Or(row.Brief, strings.TrimSpace(row.Label)))
			}
		}
	}
	if r.Update.State == "available" {
		out = append(out, r.Update.Latest+" available")
	}
	return out, fails
}
