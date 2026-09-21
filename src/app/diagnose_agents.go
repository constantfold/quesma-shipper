package app

import (
	"cmp"
	"fmt"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

const sidecarFamily = "project-map"

func agentRows(probes []sourceProbe, names map[string]string, up lastUpload, now time.Time, verbose bool) (rows []Row, agents, files int) {
	var order []string
	byFam := map[string][]sourceProbe{}
	for _, pr := range probes {
		f := familyOf(pr.src)
		if _, seen := byFam[f]; !seen {
			order = append(order, f)
		}
		byFam[f] = append(byFam[f], pr)
	}
	for _, f := range order {
		if f == sidecarFamily && !verbose {
			continue
		}
		famRows, collecting, famFiles := familyRows(cmp.Or(names[f], f), byFam[f], familyUploadFor(byFam[f], up), now, verbose)
		rows = append(rows, famRows...)
		if collecting && f != sidecarFamily {
			agents++
		}
		files += famFiles
	}
	return rows, agents, files
}

func familyRows(name string, probes []sourceProbe, up familyUpload, now time.Time, verbose bool) (rows []Row, collecting bool, files int) {
	var parts []string
	var issues []Row
	var disabled []Row
	var deferred []Row
	sniffed := ""
	absent := 0
	var noMatch []config.ResolvedSource

	// Every per-part warning is the same row shape; short is what the rollup line says went wrong.
	warn := func(part, short, detail, fix string) Row {
		return Row{Sev: SevWarn, Sub: true, Label: "  " + part,
			Brief: name + " " + part + ": " + short, Detail: detail, Fix: fix}
	}

	for _, pr := range probes {
		src, d := pr.src, pr.d
		part := partName(src)
		if !src.Enabled {
			disabled = append(disabled, Row{Sev: SevDim, Label: "  " + part, Detail: "disabled by configuration"})
			continue
		}
		if pr.err != nil {
			issues = append(issues, warn(part, "discovery error",
				fmt.Sprintf("error: %v", pr.err),
				fmt.Sprintf("check sources[%s] in config", src.ID)))
			continue
		}
		if d.Deferred {
			deferred = append(deferred, Row{Sev: SevDim, Sub: true, Label: "  " + part, Detail: d.Reason})
			continue
		}
		switch d.Health {
		case sources.Collected:
			collecting = true
			files += len(d.Candidates)
			parts = append(parts, part)
			if d.AgentVersion != "" {
				sniffed = d.AgentVersion
			}
			if d.Sniff != "" && d.Sniff != sources.SniffOK {
				issues = append(issues, warn(part, "unexpected format",
					"content does not look like the expected format",
					"the agent may have changed formats, `quesma-shipper preview` shows what would ship"))
			}
		case sources.AgentAbsent:
			absent++
		case sources.RootPresentNoMatch:
			if d.Ignored {
				disabled = append(disabled, Row{Sev: SevDim, Label: "  " + part, Detail: d.Reason})
				break
			}
			noMatch = append(noMatch, src)
		case sources.MatchPresentUnreadable:
			issues = append(issues, warn(part, "unreadable",
				"found but unreadable, "+d.Reason,
				"fix permissions on the store"))
		default:
			issues = append(issues, warn(part, string(d.Health),
				string(d.Health)+", "+d.Reason, ""))
		}

		if d.Unreadable > 0 && d.Health != sources.MatchPresentUnreadable {
			issues = append(issues, warn(part, "some files unreadable",
				fmt.Sprintf("%d files could not be read - %s", d.Unreadable, d.UnreadableReason),
				"first failing path: "+d.UnreadableExample))
		}
		if len(d.Oversize) > 0 {
			largest := largestOversize(d.Oversize)
			issues = append(issues, warn(part, "files over the size cap",
				fmt.Sprintf("%d files over the %s cap are never collected (largest %s)",
					len(d.Oversize), HumanBytes(largest.Limit), HumanBytes(largest.Size)),
				fmt.Sprintf("raise sources[%s].max_file_bytes to collect them", src.ID)))
		}
		issues = append(issues, enricherIssues(name, src)...)
	}

	for _, src := range noMatch {
		if collecting {
			if verbose {
				disabled = append(disabled, Row{Sev: SevDim, Sub: true, Detail: "no " + partName(src) + " files yet"})
			}
			continue
		}
		issues = append(issues, Row{Sev: SevWarn, Sub: true,
			Brief:  name + ": nothing found in " + HomeTilde(src.Root),
			Detail: "nothing found in " + HomeTilde(src.Root) + ", " + name + " may have changed where it writes"})
	}

	if !collecting && len(issues) == 0 {
		if len(deferred) > 0 {
			return append([]Row{{Sev: SevDim, Label: name, Name: true, Detail: deferred[0].Detail}}, disabled...), false, 0
		}
		if len(disabled) > 0 {
			return append([]Row{{Sev: SevDim, Label: name, Detail: "disabled by configuration"}}, disabled...), false, 0
		}
		if absent > 0 {
			return []Row{{Sev: SevDim, Label: name, Name: true, Detail: "not installed"}}, false, 0
		}
	}

	head := Row{Sev: SevOK, Label: name, Name: true, Tag: sniffed}
	switch {
	case collecting:
		head.Detail = CountNoun(files, "file")
		if verbose && len(parts) > 1 {
			head.Detail += " (" + strings.Join(parts, ", ") + ")"
		}
		if h := claudeHeadline(probes, verbose); h != "" {
			head.Detail = h
		}
	default:
		head.Sev = SevWarn
		head.Detail = "present but nothing is collected"
		head.Brief = name + ": nothing collected"
	}

	if collecting && (up.recorded || up.pending > 0) && (verbose || up.failed > 0) {
		detail := ""
		switch {
		case up.recorded && up.shipped > 0:
			detail = fmt.Sprintf("%s, %s sent", Ago(up.at, now), CountNoun(up.shipped, "file"))
		case up.recorded:
			detail = fmt.Sprintf("%s, nothing new", Ago(up.at, now))
		default:
			detail = "none yet"
		}
		if up.failed > 0 {
			detail += fmt.Sprintf(", %d failed", up.failed)
		}
		if up.pending > 0 {
			detail += fmt.Sprintf(", %s changed since", CountNoun(up.pending, "file"))
		}
		row := Row{Sev: SevDim, Sub: true, Label: "  last upload", Detail: detail}
		if up.failed > 0 {
			row.Sev = SevWarn
			row.Brief = name + ": upload failures"
			row.Fix = "`quesma-shipper log` shows each file's outcome"
		}
		issues = append([]Row{row}, issues...)
	}
	for _, issue := range issues {
		if issue.Sev == SevWarn {
			head.Sev = SevWarn
			head.Rollup = true
			break
		}
	}
	rows = append(append([]Row{head}, issues...), deferred...)
	return append(rows, disabled...), collecting, files
}

func claudeHeadline(probes []sourceProbe, verbose bool) string {
	sessions := 0
	projects := map[string]bool{}
	var extras []string
	for _, pr := range probes {
		if pr.src.Family != "claude-code" {
			return ""
		}
		if !pr.src.Enabled || pr.err != nil || pr.d.Health != sources.Collected {
			continue
		}
		if pr.src.ID != "claude-code-transcripts" {
			extras = append(extras, partName(pr.src))
			continue
		}
		for _, c := range pr.d.Candidates {
			if strings.HasSuffix(c.RelPath, ".jsonl") {
				sessions++
			}
			if rest, ok := strings.CutPrefix(c.RelPath, "projects/"); ok {
				if proj, _, found := strings.Cut(rest, "/"); found {
					projects[proj] = true
				}
			}
		}
	}
	if sessions == 0 || len(projects) == 0 {
		return ""
	}
	h := fmt.Sprintf("%s in %s", CountNoun(sessions, "session"), CountNoun(len(projects), "project"))
	if verbose && len(extras) > 0 {
		h += ", plus " + strings.Join(extras, " and ")
	}
	return h
}

func partName(src config.ResolvedSource) string {
	if src.Family != "" {
		if p := strings.TrimPrefix(src.ID, src.Family+"-"); p != src.ID && p != "" {
			return p
		}
	}
	return src.ID
}
