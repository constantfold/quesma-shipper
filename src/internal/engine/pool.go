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

// fileJob is one candidate, complete.
type fileJob struct {
	idx  int
	cand sources.Candidate
	fp   Fingerprint
	seen bool
}

// fileResult is what comes back: what was decided, and what the loop thread must make
// durable. Neither leg commits anything, because the store has exactly one writer.
type fileResult struct {
	idx     int
	outcome FileOutcome
	intent  intent

	// unit is the raw bytes staged for the enricher, carried out through every later exit.
	unit *transforms.RawUnit

	// bytes is the candidate's size, released back to the in-flight gate when folded.
	bytes int64

	// pending lives only between the compute leg and the loop thread that stages it.
	pending *pendingPut

	// unavailable stops this run's uploads without outcome.Fatal's permanent-kill meaning.
	unavailable bool
	loadWarning string
}

// intent is the durable write a file's outcome asks for; only the loop thread applies it.
type intent struct {
	kind   intentKind
	key    Key
	fp     Fingerprint
	reason string // backoff reason
}

type intentKind int

const (
	intentNone    intentKind = iota
	intentRefresh            // unchanged content: refresh size/mtime
	intentShipped            // the only durable step, after a verified PUT
	intentBackoff            // a read or scrub failure holds the file off
)

// sourcePass is one source's file pass. Every field belongs to the loop goroutine.
type sourcePass struct {
	o     Options
	store *commitBuffer
	src   sources.Resolved
	disc  sources.Discovery
	rep   *Report
	out   *SourceOutcome

	// budget is the run-wide max_files_per_run remainder: reserved at admission, refunded in fold.
	budget  *int
	staging bool

	// Index-addressed, so the report and enricher input keep candidate order however work finishes.
	slots  []FileOutcome
	filled []bool
	units  []*transforms.RawUnit

	decided       int // what Progress reports as done
	inFlightBytes int64
	fatal         bool // the first refusal has landed; admit nothing more
	fatalReason   string

	// staged is the authorization accumulator; it belongs to the loop goroutine alone.
	staged *batcher

	// uploadHalted is fatal's non-permanent twin: this run sends and commits nothing more.
	uploadHalted bool
	haltReason   string

	// unchangedElided counts unchanged decisions not written per-file, for the one aggregate entry.
	unchangedElided int
}

// concurrency is how many files are read, scrubbed and sealed at once: GOMAXPROCS, because the
// expensive steps are pure CPU and single-threaded per file. Not configuration; Workers is a pin.
func (o Options) concurrency(candidates int) int {
	w := o.Workers
	if w <= 0 {
		w = runtime.GOMAXPROCS(0)
	}
	return max(1, min(w, candidates))
}

// uploadConcurrency is how many PUTs ride the network at once: 8x compute, because an upload holds
// no core and the extra width overlaps a group's PUTs with the next group's sealing.
func (o Options) uploadConcurrency(compute int) int {
	if o.UploadWorkers > 0 {
		return o.UploadWorkers
	}
	return 8 * compute
}

func (p *sourcePass) run(ctx context.Context) error {
	n := len(p.disc.Candidates)
	computeLimit := p.o.concurrency(n)
	uploadLimit := p.o.uploadConcurrency(computeLimit)
	// A file in flight holds exactly one slot at a time, so this many can exist at once.
	limit := computeLimit + uploadLimit
	p.slots = make([]FileOutcome, n)
	p.filled = make([]bool, n)
	p.units = make([]*transforms.RawUnit, n)

	// Buffered to the in-flight limit, so a goroutine never blocks handing a result back.
	results := make(chan fileResult, limit)
	// A group can never hold more than the in-flight limit, so a batch goroutine never blocks.
	batches := make(chan []fileResult, limit)
	computeSlots := make(chan struct{}, computeLimit)
	uploadSlots := make(chan struct{}, uploadLimit)

	// Half the upload budget bounds a group below uploadLimit, so seal and PUT overlap.
	p.staged = &batcher{
		maxObjects: max(1, min(maxBatchObjects, uploadLimit/2)),
		send: func(items []stagedUpload) {
			// One authorization, then one PUT per member. The group holds ONE upload slot for its
			// whole life; the port bounds the fan-out inside.
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
	// settle releases a decided file's slot and gate share, then folds it; every exit ends here.
	settle := func(r fileResult) {
		inFlight--
		p.inFlightBytes -= r.bytes
		p.fold(r)
	}
	for {
		for inFlight < limit && p.canAdmit(ctx, next, inFlight, &stopped) {
			job := fileJob{idx: next, cand: p.disc.Candidates[next]}
			job.fp, job.seen = p.store.Get(Key{
				SourceID:   p.src.ID,
				NativePath: job.cand.Path,
			})
			p.inFlightBytes += job.cand.Size
			go func() {
				computeSlots <- struct{}{}
				r, pending := p.o.prepareFile(ctx, job, p.src, p.disc, p.staging)
				<-computeSlots
				// A sealed object goes back to the loop thread to join an authorization group.
				r.pending = pending
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
			if r.pending != nil {
				if d, final := p.stageUpload(r); final {
					settle(d)
				}
				continue
			}
			settle(r)
		case done := <-batches:
			for _, r := range done {
				settle(r)
			}
			// Sending the objects already accumulated would repeat one verdict per sealed sibling.
			for _, d := range p.drainStaged() {
				settle(d)
			}
		}
	}

	p.assemble()

	// The aggregate for the unchanged entries fold elided, written even if a refusal ended the pass.
	if p.unchangedElided > 0 {
		noun := "files"
		if p.unchangedElided == 1 {
			noun = "file"
		}
		_ = p.o.Log.Append(auditlog.Entry{
			Decision:      auditlog.DecisionUnchanged,
			SourceID:      p.src.ID,
			ConfigVersion: p.o.Plan.ConfigVersion,
			Reason:        fmt.Sprintf("%d %s unchanged by size and mtime, not opened; per-file entries elided", p.unchangedElided, noun),
		})
	}

	// Stop the whole run on a refusal: it has nowhere to put anything more it collects.
	if p.fatal {
		_ = p.o.Log.Append(auditlog.Entry{
			Decision: auditlog.DecisionFailed,
			SourceID: p.src.ID,
			Reason:   "run abandoned: " + p.fatalReason,
		})
		return fmt.Errorf("%w: collection stopped after %d of %d files; "+
			"this install may have been revoked or re-enrolled elsewhere. "+
			"`quesma-shipper doctor` reports what the control plane says",
			formats.ErrCredentialsRefused, len(p.out.Files), len(p.disc.Candidates))
	}
	// Not a kill: nothing new was committed, and the next tick tries again.
	if p.uploadHalted {
		p.out.Reason = "uploads stopped: " + p.haltReason
		_ = p.o.Log.Append(auditlog.Entry{
			Decision: auditlog.DecisionFailed,
			SourceID: p.src.ID,
			Reason:   p.out.Reason,
		})
		return fmt.Errorf("%w: collection stopped after %d of %d files; "+
			"nothing new was committed and the next run retries. %s",
			ErrUploadUnavailable, len(p.out.Files), len(p.disc.Candidates), p.haltReason)
	}
	if stopped != nil {
		return stopped
	}
	// Truncation is a budget verdict only; cancellation and refusal have already returned above.
	if next < n {
		p.rep.Truncated = true
		p.out.Remaining = n - next
		p.rep.Remaining += n - next
	}
	return nil
}

// canAdmit is every gate on starting one more file, in the order they matter.
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
	// Memory, not concurrency: the memstat limit was derived from ONE worst-case file, so the sum
	// of raw bytes in flight is held to the same figure. A file larger than the gate runs alone.
	if sz := p.disc.Candidates[next].Size; inFlight > 0 && p.inFlightBytes+sz > platform.MaxInFlightBytes() {
		return false
	}
	// Budget is RESERVED here and refunded in fold, which is what makes overshoot impossible.
	*p.budget--
	return true
}
