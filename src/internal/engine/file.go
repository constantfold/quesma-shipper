package engine

import (
	"context"
	"hash/fnv"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// Per-file collection. The order is the invariant: pre-filter, content hash, scrub, seal, PUT,
// and only then the commit, so a crash above it re-runs the file onto the same key rather than
// losing it. The seal/PUT split exists because the two legs wait on different slots.

// pendingPut is a sealed object waiting for an upload slot, so the compute slot can be released.
type pendingPut struct {
	obj  []byte
	md   map[string]string
	next Fingerprint // committed on a successful PUT; fresh, so Attempts resets
}

// prepareFile reads, scrubs and seals; a result with pending set still needs an upload.
func (o Options) prepareFile(ctx context.Context, job fileJob, src sources.Resolved, disc sources.Discovery, staging bool) fileResult {
	cand := disc.Candidates[job.idx]
	res := fileResult{idx: job.idx, outcome: FileOutcome{SourceID: src.ID, NativePath: cand.Path, RelPath: cand.RelPath}}
	out := &res.outcome
	fp, seen := job.fp, job.seen

	if fp.Parked && o.Now().Before(fp.BackoffUntil) {
		out.Decision = auditlog.DecisionSkipped
		out.Reason = "parked until " + fp.BackoffUntil.Format(time.RFC3339) + ": " + fp.LastError
		return res
	}

	// Cheap pre-filter; a staged file changed within the recompute window is still read, for its enricher.
	if seen && fp.SourceSize == cand.Size && fp.SourceMTime.Equal(cand.MTime) && fp.SourceHash != "" &&
		!(staging && o.Now().Sub(cand.MTime) < recomputeWindow) {
		out.Decision, out.Reason = auditlog.DecisionUnchanged, "size and mtime unchanged"
		return res
	}

	payload, err := cand.Load(ctx)
	if err != nil {
		failAndBackOff(o, &res, fp, err.Error())
		return res
	}
	raw, mtime := payload.Bytes, payload.MTime
	res.loadWarning, out.Reason = payload.Warning, payload.Warning
	out.BytesIn = int64(len(raw))
	sourceHash := transforms.Hash(raw)

	// The enricher sees exactly the bytes that shipped, never a file it re-opened mid-append.
	if staging {
		res.unit = &transforms.RawUnit{NativePath: cand.Path, Content: raw, SourceHash: sourceHash}
	}

	// An mtime-only change refreshes the stat and ships nothing.
	if seen && sourceHash == fp.SourceHash {
		out.Decision, out.Reason = auditlog.DecisionUnchanged, "content hash unchanged"
		if !o.DryRun {
			// Clears any park: the read succeeded and its hash matches one only a completed ship wrote.
			refreshed := Fingerprint{SourceSize: cand.Size, SourceMTime: cand.MTime, SourceHash: fp.SourceHash,
				Enricher: fp.Enricher, OutputHash: fp.OutputHash}
			res.commit = &refreshed
		}
		return res
	}

	// Drift signal only: the whole file ships regardless, but truncation stops looking like growth.
	if seen && cand.Size < fp.SourceSize {
		out.Reason = "file shrank: truncation or rewrite"
	}

	jsonl := src.Sniff != nil && src.Sniff.Kind == "jsonl"
	scrubbed, err := scrubSource(src, raw, jsonl, o.scrub, o.scrubErr)
	if err != nil {
		failAndBackOff(o, &res, fp, "scrub failed closed: "+err.Error())
		return res
	}
	out.Density, out.RuleHits = scrubbed.Density(), scrubbed.RuleHits

	objectKey, err := o.mirrorKey(src.ID, cand.RelPath)
	if err != nil {
		out.Decision, out.Reason = auditlog.DecisionFailed, err.Error()
		return res
	}
	out.ObjectKey = objectKey

	m := o.baseManifest(src, cand.Path, sourceHash, scrubbed)
	m.PayloadMTime = &mtime
	m.AgentVersion = disc.AgentVersion
	if m.Redaction != nil {
		m.Redaction.ScanMode = scrubbed.ScanMode
	}
	if disc.Sniff != "" {
		m.ShapeSniff = string(disc.Sniff)
	}
	res.pending = o.sealPrepared(out, m, scrubbed.Out, Fingerprint{SourceSize: cand.Size, SourceMTime: cand.MTime, SourceHash: sourceHash})
	return res
}

// Both paths seal before preview stops; only a real upload receives a pending commit.
func (o Options) sealPrepared(out *FileOutcome, m transforms.Manifest, payload []byte, next Fingerprint) *pendingPut {
	obj, sealed, err := transforms.Seal(m, payload, o.Recipients)
	if err != nil {
		out.Decision, out.Reason = auditlog.DecisionFailed, err.Error()
		return nil
	}
	out.BytesOut = int64(len(obj))
	if o.DryRun {
		out.Decision = auditlog.DecisionShipped
		if out.Derived {
			out.Reason = "would ship derived object (preview)"
		} else if out.Reason == "" {
			out.Reason = "would ship (preview)"
		}
		return nil
	}
	return &pendingPut{obj: obj, md: sealed.ObjectMetadata(), next: next}
}

// failAndBackOff parks a file with no attempt limit, since giving up silently loses data.
func failAndBackOff(o Options, res *fileResult, fp Fingerprint, reason string) {
	res.outcome.Decision, res.outcome.Reason = auditlog.DecisionParked, reason
	if o.DryRun {
		return
	}
	next := fp
	next.Attempts++
	next.Parked, next.LastError = true, reason
	// Spread by the file's own key so correlated failures do not all wake in the same second.
	h := fnv.New64a()
	_, _ = h.Write([]byte(res.outcome.SourceID))
	_, _ = h.Write([]byte(res.outcome.NativePath))
	next.BackoffUntil = o.Now().Add(backoffFor(next.Attempts, h.Sum64()))
	res.commit = &next
}

func scrubSource(src sources.Resolved, raw []byte, jsonl bool, scrubber *transforms.Scrubber, scrubErr error) (transforms.Result, error) {
	if src.Scrub != nil && !*src.Scrub {
		return transforms.Result{Out: raw, BytesTotal: len(raw)}, nil
	}
	if scrubErr != nil {
		return transforms.Result{}, scrubErr
	}
	return scrubber.Scrub(raw, transforms.Hint{Family: src.Family, JSONL: jsonl})
}

// backoffFor is a minute, doubling to an hour, less up to 12.5% deterministic jitter from spread.
func backoffFor(attempt int, spread uint64) time.Duration {
	d := min(time.Minute<<min(attempt, 8), time.Hour)
	return d - time.Duration(spread%9)*d/64
}
