package cursorjoin

// bubbleState is what the pass has concluded about one bubble. used is per bubble because a
// match may land behind the cursor: within one turn the store's header order and the transcript's
// block order can disagree. ev and n record the evidence the consumption was made on, which is
// what repeat detection compares a later claimant against. declined bars a bubble an ambiguous
// verdict refused to decide about from every later fallback.
type bubbleState struct {
	used, declined bool
	ev             evidence
	n              int
}

// How far from the cursor matchBlock will look for a bubble to CONSUME. Evidence decides between
// nearby bubbles; unbounded, one coincidental match drags the cursor past every real bubble
// behind it, each of those then a mismatch. Repeat detection is exempt: it consumes nothing, and
// a deduped re-run's original can sit a whole subagent back.
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
	// The block relates to a bubble an earlier event consumed exactly as that consumer did:
	// the store recorded one bubble for a call the agent ran more than once.
	matchRepeat
	// The evidence tells two stories at once — a deduped re-run, or a second run the store
	// recorded argument-less — and attaching under either reading is wrong under the other.
	// Nothing is attached, and the returned index is the undecided bubble.
	matchAmbiguous
)

// matchBlock finds the bubble for one content block: forward from the cursor first, then a
// bounded look-behind over bubbles the forward scans skipped. It also returns the evidence the
// match was made on, which the caller records per bubble for repeat detection.
func matchBlock(blk block, role string, events []*bubble, cursor int, state []bubbleState) (int, matchOutcome, evidence, int) {
	wantType := 2
	if role == "user" {
		wantType = 1
	}

	// weigh is one candidate's evidence, shared by both scan directions. The second value is
	// argsEvidence's strength; text evidence has no gradation, so its positives carry 1.
	weigh := func(b *bubble) (evidence, int) {
		if b.Type != 0 && b.Type != wantType {
			return evidenceNegative, 0
		}
		switch blk.Type {
		case "tool_use":
			if b.ToolFormerData == nil {
				return evidenceNegative, 0
			}
			// Arguments, not names: the transcript's display name and the store's
			// internal name differ, so the arguments are what tells two calls of the
			// same tool apart.
			return argsEvidence(blk.Input, b.ToolFormerData)

		case "text":
			if b.ToolFormerData != nil {
				return evidenceNegative, 0
			}
			// A reasoning bubble aligns only on real overlap: the lenient empty-side
			// rule below would let an empty text block consume it.
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

	// A positive is not returned on sight: two bubbles can both agree in full, and the one
	// agreeing on MORE of the call is the call — strength ranks positives, position tie-breaks.
	// Lesser grades are collected here and ranked only after both scans, because a partial
	// identifies the call only when it is discriminative: see the ranking below. Name
	// compatibility gates only the grades where position is the whole claim.
	bestPos, bestPosN := -1, 0
	partials := 0
	fwdPartial, fwdNeutral, fwdWeak := -1, -1, -1
	for i := cursor; i < len(events) && i < cursor+lookAhead; i++ {
		// Nothing at or past the cursor is consumed — consuming a bubble always
		// advances the cursor past it — so this scan needs no used check.
		if state[i].declined {
			continue
		}
		ev, n := weigh(events[i])
		switch ev {
		case evidencePositive:
			if n > bestPosN {
				bestPos, bestPosN = i, n
			}
		case evidencePartial:
			partials++
			if fwdPartial < 0 {
				fwdPartial = i
			}
		case evidenceNeutral:
			if fwdNeutral < 0 && (blk.Type != "tool_use" || namesCompatible(string(blk.Name), events[i].ToolFormerData)) {
				fwdNeutral = i
			}
		case evidenceWeak:
			if fwdWeak < 0 && namesCompatible(string(blk.Name), events[i].ToolFormerData) {
				fwdWeak = i
			}
		}
	}
	if bestPos >= 0 {
		return bestPos, matchFound, evidencePositive, bestPosN
	}

	// Look-behind, over what the forward scans stepped over: within one turn the store's header
	// order and the transcript's block order can disagree, so a call's own bubble can end up
	// behind the cursor. A bubble whose arguments agree in full is the same call wherever the
	// header order put it; on any lesser grade a forward candidate wins, since a bubble behind
	// the cursor has been passed over once already.
	repeat := false
	repeatEv, repeatN := evidenceNegative, 0
	bhdPartial, bhdNeutral, bhdWeak := -1, -1, -1
	for i := cursor - 1; i >= 0; i-- {
		if state[i].used {
			// A consumed bubble still testifies, but only to a block relating to it
			// exactly as its consumer did: a claimant agreeing better is the bubble's
			// real owner arriving after a positional fallback took it, and one agreeing
			// worse is a different call sharing values with it. Unbounded, unlike the
			// windows — nothing is consumed here.
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
			// No positional look-behind for prose: text that did not overlap is a far
			// weaker claim than an argument-less tool call at a known position.
			continue
		}
		switch ev {
		case evidencePositive:
			if n > bestPosN {
				bestPos, bestPosN = i, n
			}
		case evidencePartial:
			partials++
			if bhdPartial < 0 {
				bhdPartial = i
			}
		case evidenceNeutral:
			if bhdNeutral < 0 && namesCompatible(string(blk.Name), events[i].ToolFormerData) {
				bhdNeutral = i
			}
		case evidenceWeak:
			if bhdWeak < 0 && namesCompatible(string(blk.Name), events[i].ToolFormerData) {
				bhdWeak = i
			}
		}
	}
	if bestPos >= 0 {
		return bestPos, matchFound, evidencePositive, bestPosN
	}

	// A lone partial wins outright, either window: it is the only bubble carrying that value.
	// Plural partials cannot discriminate — every sibling grep in a turn agrees through the
	// shared workspace path — so they join the positional pool with the neutrals, where forward
	// beats look-behind and first-in-window decides. Weak candidates come last: their values
	// half-belong to some other call.
	best := -1
	if partials == 1 {
		best = fwdPartial
		if best < 0 {
			best = bhdPartial
		}
	} else {
		fwdTier := fwdNeutral
		if fwdPartial >= 0 && (fwdTier < 0 || fwdPartial < fwdTier) {
			fwdTier = fwdPartial
		}
		bhdTier := max(bhdNeutral, bhdPartial)
		switch {
		case fwdTier >= 0:
			best = fwdTier
		case bhdTier >= 0:
			best = bhdTier
		case fwdWeak >= 0:
			best = fwdWeak
		default:
			best = bhdWeak
		}
	}

	if repeat {
		// Three shapes contradict the dedup reading. An unconsumed bubble agreeing in full
		// anywhere in the store proves the run WAS recorded, just outside the windows, so the
		// loud outcome stands. A candidate explaining the block at least as well as the
		// consumed bubble leaves the dedup reading nothing to offer — edit_file_v2 records
		// only the path, so a turn of edits to one file is all mutual repeats otherwise. And a
		// candidate recording nothing at all may be the second run itself, undecidably.
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
		// The repeat outranks what remains: preferring a worse-agreeing candidate would
		// attach a different call's result and consume the bubble that call needs.
		return -1, matchRepeat, evidenceNegative, 0
	}
	if best >= 0 {
		ev, n := weigh(events[best])
		return best, matchFound, ev, n
	}
	return -1, matchNone, evidenceNegative, 0
}
