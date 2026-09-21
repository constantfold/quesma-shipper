package cursorjoin

// Consumption evidence detects repeats; declined bubbles stay unavailable after an ambiguous match.
type bubbleState struct {
	used, declined bool
	ev             evidence
	n              int
}

// Bound consumption so a coincidental match cannot skip the conversation; repeat detection is unbounded.
const (
	lookAhead  = 16
	lookBehind = 64
)

// matchOutcome is what matchBlock concluded about one content block.
type matchOutcome int

const (
	// No bubble accounts for the block; the caller classifies it as mismatch or tail.
	matchNone matchOutcome = iota
	// The returned index is the block's bubble.
	matchFound
	// The store deduplicated a call already consumed with the same evidence.
	matchRepeat
	// Deduplication and a new argument-less call are indistinguishable; attach neither.
	matchAmbiguous
)

// matchBlock returns the chosen bubble and its evidence for later repeat detection.
func matchBlock(blk block, role string, events []*bubble, cursor int, state []bubbleState) (int, matchOutcome, evidence, int) {
	weigh := func(b *bubble) (evidence, int) { return blk.evidenceFor(b, role) }

	// Forward positives win; lesser grades wait until both windows have been searched.
	fwd, behind := newMatchWindow(), newMatchWindow()
	for i := cursor; i < min(len(events), cursor+lookAhead); i++ {
		if !state[i].declined {
			ev, n := weigh(events[i])
			fwd.consider(i, ev, n, blk, events[i])
		}
	}
	if fwd.positive >= 0 {
		return fwd.positive, matchFound, evidencePositive, fwd.strength
	}

	// Store and transcript order can differ within a turn, leaving real matches behind the cursor.
	repeat := false
	repeatEv, repeatN := evidenceNegative, 0
	for i := cursor - 1; i >= 0; i-- {
		if state[i].used {
			// Only identical consumption evidence supports a repeat, at any distance.
			if blk.Type == "tool_use" && state[i].ev >= evidencePartial {
				if ev, n := weigh(events[i]); ev == state[i].ev && n == state[i].n {
					repeat = true
					if ev > repeatEv || (ev == repeatEv && n > repeatN) {
						repeatEv, repeatN = ev, n
					}
				}
			}
			continue
		}
		if i < cursor-lookBehind || state[i].declined {
			continue
		}
		ev, n := weigh(events[i])
		if blk.Type != "tool_use" && ev != evidencePositive {
			// Prose needs actual overlap to match behind the cursor.
			continue
		}
		behind.consider(i, ev, n, blk, events[i])
	}
	if behind.positive >= 0 {
		return behind.positive, matchFound, evidencePositive, behind.strength
	}

	best := fallbackCandidate(fwd, behind)

	if repeat {
		// A fresh positive anywhere rules out deduplication; report the out-of-window mismatch.
		for i := range events {
			if state[i].used || state[i].declined {
				continue
			}
			if ev, _ := weigh(events[i]); ev == evidencePositive {
				return -1, matchNone, evidenceNegative, 0
			}
		}
		if best >= 0 {
			ev, n := weigh(events[best])
			if ev == evidenceNeutral {
				return best, matchAmbiguous, evidenceNeutral, 0
			}
			if ev > repeatEv || (ev == repeatEv && n >= repeatN) {
				return best, matchFound, ev, n
			}
		}
		// A weaker candidate belongs to another call; keep its bubble available.
		return -1, matchRepeat, evidenceNegative, 0
	}
	if best >= 0 {
		ev, n := weigh(events[best])
		return best, matchFound, ev, n
	}
	return -1, matchNone, evidenceNegative, 0
}

// Each window keeps its first candidate per grade; positive ties favor stronger evidence.
type matchWindow struct {
	positive, partial, neutral, weak int
	strength, partials               int
}

func newMatchWindow() matchWindow {
	return matchWindow{positive: -1, partial: -1, neutral: -1, weak: -1}
}

func (w *matchWindow) consider(i int, ev evidence, n int, blk block, b *bubble) {
	switch ev {
	case evidencePositive:
		if n > w.strength {
			w.positive, w.strength = i, n
		}
	case evidencePartial:
		w.partials++
		if w.partial < 0 {
			w.partial = i
		}
	case evidenceNeutral, evidenceWeak:
		if blk.Type == "tool_use" && !namesCompatible(string(blk.Name), b.ToolFormerData) {
			return
		}
		first := &w.neutral
		if ev == evidenceWeak {
			first = &w.weak
		}
		if *first < 0 {
			*first = i
		}
	}
}

// A unique partial identifies a call. Otherwise position wins: forward, behind, then weak evidence.
func fallbackCandidate(fwd, behind matchWindow) int {
	if fwd.partials+behind.partials == 1 {
		return max(fwd.partial, behind.partial)
	}
	first := fwd.neutral
	if fwd.partial >= 0 && (first < 0 || fwd.partial < first) {
		first = fwd.partial
	}
	for _, i := range []int{first, max(behind.neutral, behind.partial), fwd.weak, behind.weak} {
		if i >= 0 {
			return i
		}
	}
	return -1
}

func (blk block) evidenceFor(b *bubble, role string) (evidence, int) {
	wantType := 2
	if role == "user" {
		wantType = 1
	}
	if b.Type != 0 && b.Type != wantType {
		return evidenceNegative, 0
	}
	switch blk.Type {
	case "tool_use":
		if b.ToolFormerData == nil {
			return evidenceNegative, 0
		}
		// Display and internal names differ; arguments distinguish calls of the same tool.
		return argsEvidence(blk.Input, b.ToolFormerData)

	case "text":
		if b.ToolFormerData != nil {
			return evidenceNegative, 0
		}
		// Empty text must not consume a reasoning bubble.
		if rt := b.reasoningText(); rt != "" {
			if strictOverlap(string(blk.Text), rt) {
				return evidencePositive, 1
			}
			return evidenceNegative, 0
		}
		if strictOverlap(string(blk.Text), b.Text) {
			return evidencePositive, 1
		}
		if textOverlap(string(blk.Text), b.Text) {
			// The lenient rule confirms nothing: positional evidence only.
			return evidenceNeutral, 0
		}
		return evidenceNegative, 0

	default:
		// An unknown block type means Cursor changed; the loud outcome is right.
		return evidenceNegative, 0
	}
}
