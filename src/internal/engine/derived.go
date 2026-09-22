package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// Enrichment: running an enricher and shipping what it derived. A derived object takes the same
// scrub, seal and upload path a raw file takes, being built from a database that holds auth material.

// recomputeWindow is how recently a source file must have changed for its enrichment to be
// recomputed anyway: the DB side moves on its own, and a late tool result would never be collected.
const recomputeWindow = 24 * time.Hour

// enrichersFor returns a source's enabled enrichers sorted by id, so every flush runs them in one order.
func (o Options) enrichersFor(src sources.Resolved) []transforms.Enricher {
	var out []transforms.Enricher
	for id, e := range o.Enrichers {
		if src.Enrichers[id] {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b transforms.Enricher) int { return strings.Compare(a.ID(), b.ID()) })
	return out
}

// enrichSource runs one enricher and ships whatever it derived. A non-nil error stops the run.
func (o Options) enrichSource(
	ctx context.Context,
	store *commitBuffer,
	src sources.Resolved,
	e transforms.Enricher,
	staged []transforms.RawUnit,
	out *SourceOutcome,
	rep *Report,
) error {
	out.EnricherID, out.EnricherVersion = e.ID(), e.Version()
	// The first declared database candidate that exists; empty means absent, which is not an error.
	dbPath := o.Env.FirstExistingFile(e.DBCandidates())
	res := e.Enrich(transforms.Input{Units: staged, DBPath: dbPath, ScratchDir: filepath.Join(o.StateDir, "scratch")})

	out.EnrichSkipped += res.Skipped
	out.EnrichMismatch += res.Mismatched
	out.EnrichErrors += res.Errors
	out.EnrichNotes = append(out.EnrichNotes, res.Notes...)
	out.EnrichInfos = append(out.EnrichInfos, res.Infos...)
	rep.EnrichMismatch += res.Mismatched

	// A lost window must appear in the audit log, not only a counter. Infos describe objects that
	// ship, so only notes are recorded as skipped.
	for _, note := range res.Notes {
		o.auditSource(src.ID, auditlog.Entry{Decision: auditlog.DecisionSkipped, Reason: "enrich: " + note})
	}

	// Outcomes are index-addressed so the report keeps enricher order.
	fos := make([]FileOutcome, len(res.Objects))
	var halted error
	group := &batcher{
		maxObjects: maxBatchObjects,
		send: func(items []fileResult) {
			outcomes := o.authorizeAndUpload(ctx, items)
			for i, it := range items {
				r := applyUploadOutcome(it, outcomes[i])
				store.applyIntent(&r)
				fos[r.idx] = r.outcome
				if r.outcome.Decision == auditlog.DecisionShipped {
					out.Enriched++
					rep.Shipped++
				}
				// A refusal or an unavailable plane stops this enricher; a failed PUT does not.
				if halted == nil && stopsRun(outcomes[i]) {
					halted = outcomes[i]
				}
			}
		},
	}
	for i, d := range res.Objects {
		if halted != nil {
			fos[i] = FileOutcome{
				SourceID: src.ID, NativePath: d.NativePath, BytesIn: int64(len(d.Payload)), Derived: true,
				Decision: auditlog.DecisionFailed, Reason: "not attempted: " + halted.Error(),
			}
			continue
		}
		r := o.prepareDerived(store, src, e, dbPath, d)
		r.idx = i
		if r.pending == nil {
			fos[i] = r.outcome
			continue
		}
		group.add(r)
	}
	group.flush()
	out.Files = append(out.Files, fos...)

	if halted != nil {
		out.Reason = "uploads stopped: " + halted.Error()
		o.auditSource(src.ID, auditlog.Entry{Decision: auditlog.DecisionFailed, Reason: out.Reason})
		return fmt.Errorf("enricher %s stopped: %w", e.ID(), halted)
	}
	return nil
}

// prepareDerived is the derived object's compute leg: change detection, scrub, key, manifest, seal.
func (o Options) prepareDerived(store *commitBuffer, src sources.Resolved, e transforms.Enricher, dbPath string, d transforms.Derived) fileResult {
	r := fileResult{outcome: FileOutcome{SourceID: src.ID, NativePath: d.NativePath, BytesIn: int64(len(d.Payload)), Derived: true}}
	fo := &r.outcome
	fail := func(reason string) fileResult {
		fo.Decision, fo.Reason = auditlog.DecisionFailed, reason
		return r
	}

	// Determinism supplies the change signal: an unchanged output hash means nothing to upload.
	if fp, seen := store.Get(Key{SourceID: src.ID, NativePath: d.NativePath}); seen && fp.OutputHash == d.OutputHash && fp.SourceHash != "" {
		fo.Decision, fo.Reason = auditlog.DecisionUnchanged, "enricher output hash unchanged"
		return r
	}

	res, err := scrubSource(src, d.Payload, true, o.scrub, o.scrubErr)
	if err != nil {
		return fail("scrub failed closed on derived payload: " + err.Error())
	}
	relPath := d.NativePath
	if src.Root != "" && strings.HasPrefix(relPath, src.Root) {
		relPath = strings.TrimPrefix(strings.TrimPrefix(relPath, src.Root), string(filepath.Separator))
	}
	if fo.ObjectKey, err = o.mirrorKey(src.ID, relPath); err != nil {
		return fail(err.Error())
	}

	sourceHash := transforms.Hash(d.Payload)
	ref := &EnricherRef{ID: e.ID(), Version: e.Version()}
	m := o.baseManifest(src, d.NativePath, sourceHash, res)
	// What makes this object distrustable: downstream cannot regenerate the DB-side fields.
	m.Derived = true
	m.Enricher = ref
	m.DerivedFrom = d.DerivedFrom
	m.EnrichStatus = string(d.Status)
	m.EnrichMismatches = d.Mismatches
	m.EnrichRepeats = d.Repeats
	m.EnrichTail = d.Tail
	m.EnrichAmbiguous = d.Ambiguous
	m.EnrichLineDecodeErrors = d.LineDecodeErrors
	m.DBProvenance = &transforms.DBProvenance{
		DBPath:     formats.ApplyUserPlaceholder(dbPath, o.user),
		ReadMethod: d.DBReadMethod,
		Keyspaces:  d.DBKeyspaces,
		RowsRead:   d.DBRowsRead,
	}
	r.pending = o.sealPrepared(fo, m, res.Out, Fingerprint{SourceHash: sourceHash, OutputHash: d.OutputHash, Enricher: ref})
	return r
}
