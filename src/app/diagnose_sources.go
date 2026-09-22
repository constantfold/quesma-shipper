package app

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

type sourceProbe struct {
	src     config.ResolvedSource
	d       sources.Discovery
	err     error
	pending int
}

func pending(doc engine.Document, src config.ResolvedSource, d sources.Discovery) (files int, bytes int64) {
	for _, c := range d.Candidates {
		if pendingFile(doc, src, c) {
			files++
			bytes += c.Size
		}
	}
	return files, bytes
}

func pendingFile(doc engine.Document, src config.ResolvedSource, c sources.Candidate) bool {
	if stored, known := doc.SourceSpecs[src.ID]; known && stored != src.SpecFingerprint {
		return true
	}
	fp, seen := doc.Entries[engine.Key{SourceID: src.ID, NativePath: c.Path}]
	return !seen || fp.SourceSize != c.Size || fp.SourceMTime.UnixNano() != c.MTime.UnixNano()
}

type enricherProbe struct {
	id string
	e  transforms.Enricher
	on bool
	db string // resolved database path; empty means not found
}

func probeEnrichers(src config.ResolvedSource) []enricherProbe {
	if len(src.Enrichers) == 0 {
		return nil
	}
	compiled := Enrichers()
	var out []enricherProbe
	for _, id := range slices.Sorted(maps.Keys(src.Enrichers)) {
		p := enricherProbe{id: id, e: compiled[id], on: src.Enrichers[id]}
		if p.e != nil && p.on {
			p.db = firstExistingDB(p.e)
		}
		out = append(out, p)
	}
	return out
}

func enricherIssues(name string, src config.ResolvedSource) []Row {
	var rows []Row
	for _, p := range probeEnrichers(src) {
		switch {
		case p.e == nil:
			rows = append(rows, Row{Sev: SevWarn, Sub: true, Label: "  database",
				Brief:  name + ": enricher missing from this build",
				Detail: "tool results and timestamps are not captured - enricher " + p.id + " is not in this build",
				Fix:    "`quesma-shipper update` may carry it"})
		case !p.on:
			rows = append(rows, Row{Sev: SevDim, Label: "  database",
				Detail: "enrichment disabled - no tool results, call ids or timestamps"})
		case p.db == "":
			rows = append(rows, Row{Sev: SevWarn, Sub: true, Label: "  database",
				Brief:  name + ": enrichment database not found",
				Detail: "not found, raw files only, no tool results or timestamps",
				Fix:    "looked for " + strings.Join(p.e.DBCandidates(), ", ")})
		}
	}
	return rows
}

func technicalSourceRows(pr sourceProbe) []Row {
	src := pr.src
	if !src.Enabled {
		return []Row{{Sev: SevDim, Label: src.ID, Detail: "disabled by configuration"}}
	}
	if pr.err != nil {
		return []Row{{Sev: SevWarn, Label: src.ID, Detail: fmt.Sprintf("error: %v", pr.err)}}
	}
	return append(discoveryRows(src, pr.d), enricherRows(src)...)
}

func discoveryRows(src config.ResolvedSource, d sources.Discovery) []Row {
	if d.Deferred {
		return []Row{{Sev: SevDim, Label: src.ID, Detail: d.Reason}}
	}
	head := Row{Sev: SevWarn, Label: src.ID, Detail: string(d.Health) + ", " + d.Reason}
	switch d.Health {
	case sources.Collected:
		head.Sev = SevOK
		head.Detail = fmt.Sprintf("%s - %d candidate(s)", d.Health, len(d.Candidates))
		if d.AgentVersion != "" {
			head.Detail += ", agent " + d.AgentVersion
		}
		if d.Sniff != "" && d.Sniff != sources.SniffOK {
			head.Sev = SevWarn
			head.Detail += ", sniff " + string(d.Sniff)
			head.Fix = "the agent's format may have changed under this build, `quesma-shipper preview` shows what would ship"
		}
	case sources.AgentAbsent:
		head.Sev = SevDim
	case sources.RootPresentNoMatch:
		if d.Ignored {
			head.Sev = SevDim
		} else {
			head.Fix = "the store may have moved, files there are not collected"
		}
	case sources.MatchPresentUnreadable:
		head.Fix = "fix permissions on the store, or the agent changed its format under this build"
	}
	rows := []Row{head}

	if d.Unreadable > 0 && d.Health != sources.MatchPresentUnreadable {
		rows = append(rows, Row{Sev: SevWarn, Label: "  unreadable",
			Detail: fmt.Sprintf("%d path(s) unreadable during discovery - %s", d.Unreadable, d.UnreadableReason),
			Fix:    "first failing path: " + d.UnreadableExample})
	}
	if len(d.Oversize) > 0 {
		largest := largestOversize(d.Oversize)
		rows = append(rows, Row{Sev: SevWarn, Label: "  size cap",
			Detail: fmt.Sprintf("%d file(s) over the %s cap, never collected - largest %s",
				len(d.Oversize), HumanBytes(largest.Limit), HumanBytes(largest.Size)),
			Fix: fmt.Sprintf("raise sources[%s].max_file_bytes to collect them", src.ID)})
	}
	return rows
}

func doctorReport(probes []sourceProbe) formats.Report {
	var rep formats.Report
	for _, pr := range probes {
		if !pr.src.Enabled || pr.err != nil {
			continue
		}
		rep.Sources = append(rep.Sources, formats.SourceOutcome{
			SourceID:     pr.src.ID,
			Family:       pr.src.Family,
			Health:       pr.d.Health,
			Sniff:        pr.d.Sniff,
			AgentVersion: pr.d.AgentVersion,
			Reason:       pr.d.Reason,
			Oversize:     len(pr.d.Oversize),
			Unreadable:   pr.d.Unreadable,
		})
	}
	return rep
}

func enricherRows(src config.ResolvedSource) []Row {
	var rows []Row
	for _, p := range probeEnrichers(src) {
		switch {
		case p.e == nil:
			rows = append(rows, Row{Sev: SevWarn, Label: "  enricher " + p.id,
				Detail: fmt.Sprintf("declared but not in this build: enrich: no enricher %q in this build", p.id)})
		case !p.on:
			rows = append(rows, Row{Sev: SevDim, Label: "  enricher " + p.id,
				Detail: "disabled - no tool results, call ids or timestamps will be collected"})
		case p.db == "":
			rows = append(rows, Row{Sev: SevWarn, Label: fmt.Sprintf("  enricher %s@%d", p.id, p.e.Version()),
				Detail: strings.Join(p.e.DBCandidates(), ", ") + " not found, raw files only"})
		default:
			rows = append(rows, Row{Sev: SevOK, Label: fmt.Sprintf("  enricher %s@%d", p.id, p.e.Version()),
				Detail: fmt.Sprintf("reads %s (%s, keyspaces %v)", p.db, p.e.Table(), p.e.Keyspaces())})
		}
	}
	return rows
}

func firstExistingDB(e transforms.Enricher) string {
	env, err := sources.OSEnv()
	if err != nil {
		return ""
	}
	return env.FirstExistingFile(e.DBCandidates())
}

func largestOversize(o []sources.Oversize) sources.Oversize {
	return slices.MaxFunc(o, func(a, b sources.Oversize) int { return cmp.Compare(a.Size, b.Size) })
}
