package engine

import (
	"context"
	"fmt"
	"runtime"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// fileJob identifies a candidate and snapshots its committed state before concurrent preparation.
type fileJob struct {
	idx  int
	fp   Fingerprint
	seen bool
}

// fileResult is what was decided and what the loop thread must make durable; workers commit nothing.
type fileResult struct {
	idx     int
	outcome FileOutcome
	intent  intent

	// unit is the raw bytes staged for the enricher; pending owns ciphertext until upload or abandonment.
	unit    *transforms.RawUnit
	pending *pendingPut

	// unavailable stops this run's uploads without outcome.Fatal's permanent-kill meaning.
	unavailable bool
	loadWarning string
}

// intent is the durable write a file's outcome asks for; only the loop thread applies it.
type intent struct {
	kind intentKind
	key  Key
	fp   Fingerprint
}

type intentKind int

const (
	intentNone    intentKind = iota
	intentRefresh            // unchanged content: refresh size/mtime
	intentShipped            // after a verified PUT
	intentBackoff            // a read or scrub failure holds the file off
)

// sourcePass is one source's file pass. Every field belongs to the loop goroutine.
type sourcePass struct {
	o       Options
	store   *commitBuffer
	src     sources.Resolved
	disc    sources.Discovery
	rep     *Report
	out     *SourceOutcome
	budget  *int // run-wide remainder: reserved at admission, refunded in fold
	staging bool
	staged  *batcher

	// Index-addressed, so the report and enricher input keep candidate order however work finishes.
	slots []FileOutcome
	units []*transforms.RawUnit

	decided         int
	inFlightBytes   int64
	unchangedElided int

	// fatal is a refusal (admit nothing more); uploadHalted is its non-permanent twin.
	fatal        bool
	fatalReason  string
	uploadHalted bool
	haltReason   string
}

func (p *sourcePass) run(ctx context.Context) error {
	n := len(p.disc.Candidates)
	// Reading, scrubbing and sealing are pure CPU; an upload holds no core, so 8x compute lets PUTs
	// overlap sealing.
	workers := p.o.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	computeLimit := max(1, min(workers, n))
	uploadLimit := p.o.UploadWorkers
	if uploadLimit <= 0 {
		uploadLimit = 8 * computeLimit
	}
	// A file in flight holds one slot at a time, so channels sized to this never block a sender.
	limit := computeLimit + uploadLimit
	p.slots = make([]FileOutcome, n)
	p.units = make([]*transforms.RawUnit, n)

	results := make(chan fileResult, limit)
	batches := make(chan []fileResult, limit)
	computeSlots := make(chan struct{}, computeLimit)
	uploadSlots := make(chan struct{}, uploadLimit)

	// Half the upload budget bounds a group, so seal and PUT overlap. A group holds one upload slot.
	p.staged = &batcher{
		maxObjects: max(1, min(maxBatchObjects, uploadLimit/2)),
		send: func(items []fileResult) {
			go func() {
				uploadSlots <- struct{}{}
				done := p.o.sendBatch(ctx, items)
				<-uploadSlots
				batches <- done
			}()
		},
	}

	next, inFlight, computing := 0, 0, 0
	var stopped error
	settle := func(r fileResult) {
		inFlight--
		p.inFlightBytes -= p.disc.Candidates[r.idx].Size
		p.fold(r)
	}
	for {
		for inFlight < limit && p.canAdmit(ctx, next, inFlight, &stopped) {
			job := fileJob{idx: next}
			job.fp, job.seen = p.store.Get(Key{SourceID: p.src.ID, NativePath: p.disc.Candidates[next].Path})
			p.inFlightBytes += p.disc.Candidates[next].Size
			go func() {
				computeSlots <- struct{}{}
				r := p.o.prepareFile(ctx, job, p.src, p.disc, p.staging)
				<-computeSlots
				results <- r
			}()
			next++
			inFlight++
			computing++
		}
		// Nothing else can join the accumulator, so send what is held rather than wait.
		if computing == 0 {
			p.staged.flush()
		}
		if inFlight == 0 {
			break
		}
		select {
		case r := <-results:
			computing--
			if r.pending == nil {
				settle(r)
			} else if d, final := p.stageUpload(r); final {
				settle(d)
			}
		case done := <-batches:
			for _, r := range done {
				settle(r)
			}
			// Sending what already accumulated would repeat one verdict per sealed sibling.
			for _, d := range p.drainStaged() {
				settle(d)
			}
		}
	}

	p.assemble()

	// Written even if a refusal ended the pass.
	if p.unchangedElided > 0 {
		noun := "files"
		if p.unchangedElided == 1 {
			noun = "file"
		}
		p.o.auditSource(p.src.ID, auditlog.Entry{
			Decision: auditlog.DecisionUnchanged,
			Reason:   fmt.Sprintf("%d %s unchanged by size and mtime, not opened; per-file entries elided", p.unchangedElided, noun),
		})
	}

	if p.fatal {
		_ = p.o.Log.Append(auditlog.Entry{Decision: auditlog.DecisionFailed, SourceID: p.src.ID, Reason: "run abandoned: " + p.fatalReason})
		return fmt.Errorf("%w: collection stopped after %d of %d files; "+
			"this install may have been revoked or re-enrolled elsewhere. "+
			"`quesma-shipper doctor` reports what the control plane says",
			formats.ErrCredentialsRefused, len(p.out.Files), len(p.disc.Candidates))
	}
	// Not a kill: nothing new was committed, and the next tick tries again.
	if p.uploadHalted {
		p.out.Reason = "uploads stopped: " + p.haltReason
		_ = p.o.Log.Append(auditlog.Entry{Decision: auditlog.DecisionFailed, SourceID: p.src.ID, Reason: p.out.Reason})
		return fmt.Errorf("%w: collection stopped after %d of %d files; "+
			"nothing new was committed and the next run retries. %s",
			ErrUploadUnavailable, len(p.out.Files), len(p.disc.Candidates), p.haltReason)
	}
	if stopped != nil {
		return stopped
	}
	if next < n {
		p.rep.Truncated = true
		p.out.Remaining = n - next
		p.rep.Remaining += n - next
	}
	return nil
}

// canAdmit is every check on starting one more file, in the order they matter.
func (p *sourcePass) canAdmit(ctx context.Context, next, inFlight int, stopped *error) bool {
	if *stopped != nil || p.fatal || p.uploadHalted || next >= len(p.disc.Candidates) {
		return false
	}
	if err := ctx.Err(); err != nil {
		// The drain deadline arrives here: admit nothing more, but collect and commit what runs.
		*stopped = err
		return false
	}
	if *p.budget <= 0 {
		return false
	}
	// The memstat limit was derived from one worst-case file, so raw bytes in flight are held to
	// the same figure. A file larger than the limit runs alone.
	if sz := p.disc.Candidates[next].Size; inFlight > 0 && p.inFlightBytes+sz > platform.MaxInFlightBytes() {
		return false
	}
	*p.budget-- // reserved here and refunded in fold, so overshoot is impossible
	return true
}
