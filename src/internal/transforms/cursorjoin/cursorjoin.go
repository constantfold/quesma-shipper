// Package cursorjoin joins transcript intent with outcomes from Cursor’s SQLite store.
// Unexplained alignment failures ship raw JSONL with an alarm, never a misleading partial join.
package cursorjoin

import (
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources/sqliteread"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// The version travels in every derived object's manifest; bump it whenever the join's answer can change.
const (
	id      = "cursor-transcript-join"
	version = 4
)

// The declared read scope: composer records and per-turn bubbles, nothing else in the table.
const (
	table          = "cursorDiskKV"
	composerPrefix = "composerData:"
	bubblePrefix   = "bubbleId:"
)

// Enricher implements transforms.Enricher.
type Enricher struct{}

func New() *Enricher { return &Enricher{} }

func (*Enricher) ID() string       { return id }
func (*Enricher) Version() int     { return version }
func (*Enricher) Table() string    { return table }
func (*Enricher) NeedsUnits() bool { return true }

// Prefixes rather than the whole table: state.vscdb also holds checkpoints, diffs and tokens.
func (*Enricher) Keyspaces() []string { return []string{composerPrefix, bubblePrefix} }

// Compiled in, never configured, so no config layer can point this enricher at an arbitrary SQLite file.
const cursorStateDB = "Cursor/User/globalStorage/state.vscdb"

func (*Enricher) DBCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"~/Library/Application Support/" + cursorStateDB}
	case "linux":
		return []string{"~/.config/" + cursorStateDB, "~/.config/cursor/User/globalStorage/state.vscdb"}
	case "windows":
		return []string{"$APPDATA/" + cursorStateDB}
	}
	return nil
}

func (e *Enricher) Enrich(in transforms.Input) transforms.EnrichResult {
	res := transforms.EnrichResult{EnricherID: id, Version: version}

	if in.DBPath == "" {
		// Not an alarm: nothing to derive from, and the raw transcripts ship as always.
		res.Skipped = len(in.Units)
		if len(in.Units) > 0 {
			res.Notes = append(res.Notes, "no state.vscdb found: raw transcripts only")
		}
		return res
	}

	read, err := sqliteread.Read(sqliteread.Options{Path: in.DBPath, ScratchDir: in.ScratchDir, Table: table, KeyPrefixes: e.Keyspaces()})
	if err != nil {
		// Fail open: this costs the flush's DB-side fields, not the raw transcripts.
		res.Errors = len(in.Units)
		res.Notes = append(res.Notes, "state.vscdb unreadable: "+err.Error())
		return res
	}

	if read.Truncated {
		// Rows are ordered by key, so a suffix of the keyspace is missing.
		res.Notes = append(res.Notes, fmt.Sprintf("state.vscdb row cap reached at %d rows: DB-side fields are "+
			"missing for whatever sorts after the last key read", len(read.Rows)))
	}

	ix := indexRows(read.Rows)
	if ix.decodeErrors > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d store rows in the declared keyspaces did not decode "+
			"(the store schema is vendor behaviour and drifts)", ix.decodeErrors))
	}

	for _, u := range in.Units {
		// The join key: the transcript's basename is the UUID in composerData:<UUID>.
		conv, ok := strings.CutSuffix(filepath.Base(u.NativePath), ".jsonl")
		if !ok || conv == "" {
			res.Skipped++
			continue
		}
		d, note := e.joinOne(u, conv, ix, read)
		if note != "" {
			// Routed by outcome: a note on a shipped object would be reported as lost data.
			if d.Status == transforms.StatusOK {
				res.Infos = append(res.Infos, note)
			} else {
				res.Notes = append(res.Notes, note)
			}
		}
		// An alarm like the store decode note: those blocks lose enrichment even when the object ships.
		if d.LineDecodeErrors > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %d mid-file transcript lines did not decode (the line "+
				"shape is vendor behaviour and drifts): their blocks never reached the join, and the derived "+
				"object ships without their enrichment", conv, d.LineDecodeErrors))
		}
		switch d.Status {
		case transforms.StatusOK:
			res.Objects = append(res.Objects, d)
		case transforms.StatusMismatch:
			// A partial object is indistinguishable downstream from a complete one.
			res.Mismatched++
		case transforms.StatusError:
			res.Errors++
		default:
			res.Skipped++
		}
	}
	return res
}

func (e *Enricher) joinOne(u transforms.RawUnit, conv string, ix *indexed, read sqliteread.Result) (transforms.Derived, string) {
	d := transforms.Derived{
		NativePath:   u.NativePath + ".enriched.jsonl",
		DerivedFrom:  []string{u.SourceHash},
		DBReadMethod: string(read.Method),
		DBKeyspaces:  e.Keyspaces(),
		DBRowsRead:   len(read.Rows),
	}

	ordered := orderBubbles(ix.composers[conv], ix.bubbles[conv], ix.order[conv])
	if len(ordered) == 0 {
		d.Status = transforms.StatusSkipped
		return d, ""
	}

	// Dropped before alignment: left in, they would mismatch rows that never had a counterpart.
	events := slices.DeleteFunc(ordered, isScaffolding)

	a, err := alignAndRender(u.Content, events)
	if err != nil {
		d.Status = transforms.StatusError
		return d, fmt.Sprintf("%s: %v", conv, err)
	}
	// Set before the status check: Enrich reports this loss whether or not an object ships.
	d.LineDecodeErrors = a.lineDecodeErrors
	if a.mismatches > 0 {
		d.Status, d.Mismatches = transforms.StatusMismatch, a.mismatches
		return d, fmt.Sprintf("%s: %d transcript events did not align with the store; no derived object, raw "+
			"transcript ships (the join rules are vendor behaviour and drift)", conv, a.mismatches)
	}
	d.Payload, d.OutputHash, d.Status = a.out, transforms.Hash(a.out), transforms.StatusOK
	// Onto the object, not only into a note: the note dies with the flush.
	d.Repeats, d.Tail, d.Ambiguous = a.repeats, a.tail, a.ambiguous

	// Informational, not alarms: observed vendor behaviour, not rule drift.
	var infos []string
	if a.tail > 0 {
		infos = append(infos, fmt.Sprintf("%d transcript events extend past the store's last bubble", a.tail))
	}
	if a.repeats > 0 {
		infos = append(infos, fmt.Sprintf("%d transcript events repeat calls whose bubble an identical earlier event already consumed", a.repeats))
	}
	if a.ambiguous > 0 {
		infos = append(infos, fmt.Sprintf("%d transcript events the store evidence cannot decide between a deduped "+
			"re-run and a second unrecorded call — nothing attached rather than guessed", a.ambiguous))
	}
	if len(infos) > 0 {
		return d, fmt.Sprintf("%s: %s; carried native-only in the derived object", conv, strings.Join(infos, "; "))
	}
	return d, ""
}
