// align.go walks the transcript and the ordered bubbles together and renders the derived JSONL.

package cursorjoin

import (
	"bytes"
	"cmp"
	"encoding/json"
	"strings"
)

// line is one JSONL record, decoded only as far as the join needs. Scalars are flexString: a drifted
// field would reject the line, which ships as native_invalid with mismatches at zero — silent loss.
type line struct {
	Role    flexString `json:"role"`
	Message *message   `json:"message"`
}

type message struct {
	Content []block `json:"content"`
}

type block struct {
	Type  flexString      `json:"type"`
	Text  flexString      `json:"text"`
	Name  flexString      `json:"name"`
	Input json.RawMessage `json:"input"`
}

// outLine is one derived line. Native holds the original bytes verbatim. Enrich is index-aligned to
// the native blocks, never a map: lexicographic key order would sort block 10 before block 2.
type outLine struct {
	Native json.RawMessage `json:"native,omitempty"`

	// An invalid line kept as a string: a torn tail is expected, and an invalid raw value would make the
	// whole document unmarshalable. A mid-rune tear becomes U+FFFD; the raw transcript ships byte-exact.
	NativeInvalid string `json:"native_invalid,omitempty"`

	Enrich []*blockEnrich `json:"_enrich,omitempty"`
}

// blockEnrich is what the store knew and the transcript did not, such as the call id and full output.
type blockEnrich struct {
	BubbleID   string `json:"bubbleId,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`

	// ToolName is the INTERNAL name, which can differ from the transcript's display name.
	ToolName string `json:"tool_name,omitempty"`
	Status   string `json:"status,omitempty"`
	Result   string `json:"result,omitempty"`

	CreatedAt      string `json:"createdAt,omitempty"`
	RequestID      string `json:"requestId,omitempty"`
	CheckpointID   string `json:"checkpointId,omitempty"`
	TurnDurationMs int64  `json:"turnDurationMs,omitempty"`
	ModelName      string `json:"modelName,omitempty"`
}

// The transcript is the authority: an event the store cannot account for is a mismatch, an
// unmentioned bubble is skipped. Tail (store ends early, as with injected turns), repeats and
// ambiguous events ship native-only.
func alignAndRender(content []byte, events []*bubble) (alignment, error) {
	var out bytes.Buffer
	cursor := 0

	// Unmatched blocks become tail or mismatch after the pass, by the last CONSUMING match. Repeats and
	// ambiguous events move no watermark; a hole before one is still caught by a later real match.
	seq := 0
	lastMatchedSeq := -1
	var unmatched []int
	repeats := 0
	ambiguous := 0

	state := make([]bubbleState, len(events))

	// Positioned, not just counted: only the final line can be the expected torn tail.
	lineNo := 0
	invalidLines := 0
	lastInvalidLine := -1

	for raw := range bytes.SplitSeq(content, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			continue
		}
		lineNo++

		var l line
		if err := json.Unmarshal(trimmed, &l); err != nil {
			// A truncated tail is expected: Cursor's transcript writes are not atomic.
			invalidLines++
			lastInvalidLine = lineNo
			if err := writeLine(&out, outLine{NativeInvalid: string(trimmed)}); err != nil {
				return alignment{}, err
			}
			continue
		}

		// turn_ended is a terminator, not an event: it has no bubble and must not consume the cursor.
		if l.Role == "" || l.Message == nil || len(l.Message.Content) == 0 {
			if err := writeLine(&out, outLine{Native: append(json.RawMessage{}, trimmed...)}); err != nil {
				return alignment{}, err
			}
			continue
		}

		enriched := make([]*blockEnrich, len(l.Message.Content))
		matchedAny := false
		for i, blk := range l.Message.Content {
			// Reasoning arrives as a literal [REDACTED] with nothing to align to.
			if blk.Type == "text" && isRedactedReasoning(string(blk.Text)) {
				continue
			}
			idx, outcome, ev, n := matchBlock(blk, string(l.Role), events, cursor, state)
			seq++
			switch outcome {
			case matchNone:
				unmatched = append(unmatched, seq)
				continue
			case matchRepeat:
				// Nothing to attach: the consumed bubble's result belongs to its consumer.
				repeats++
				continue
			case matchAmbiguous:
				ambiguous++
				state[idx].declined = true
				continue
			}
			lastMatchedSeq = seq
			state[idx].used = true
			state[idx].ev, state[idx].n = ev, n
			if idx+1 > cursor {
				cursor = idx + 1
			}
			matchedAny = true
			enriched[i] = fromBubble(events[idx])
		}
		if !matchedAny {
			enriched = nil
		}
		if err := writeLine(&out, outLine{
			Native: append(json.RawMessage{}, trimmed...),
			Enrich: enriched,
		}); err != nil {
			return alignment{}, err
		}
	}

	a := alignment{out: out.Bytes(), repeats: repeats, ambiguous: ambiguous}
	// Exempt by position, not by kind: a torn tail is by definition terminal.
	a.lineDecodeErrors = invalidLines
	if invalidLines > 0 && lastInvalidLine == lineNo {
		a.lineDecodeErrors--
	}
	for _, s := range unmatched {
		// A transcript that matched nothing is all mismatch, not all tail.
		if lastMatchedSeq >= 0 && s > lastMatchedSeq {
			a.tail++
		} else {
			a.mismatches++
		}
	}
	return a, nil
}

// used is per bubble as a match may land behind the cursor; ev and n are the consuming evidence a
// later claimant is compared against; declined bars an undecided bubble from every later fallback.
type bubbleState struct {
	used, declined bool
	ev             evidence
	n              int
}

type alignment struct {
	out        []byte
	mismatches int
	tail       int
	repeats    int
	ambiguous  int

	// Undecodable transcript lines except a final torn tail; reported like indexed.decodeErrors.
	lineDecodeErrors int
}

// The CONSUME window: unbounded, one coincidental match drags the cursor past every real bubble behind
// it. Repeat detection is exempt: it consumes nothing, and a deduped original can sit a subagent back.
const (
	lookAhead  = 16
	lookBehind = 64
)

type matchOutcome int

const (
	// No bubble accounts for the block; the caller classifies it as mismatch or tail.
	matchNone matchOutcome = iota
	matchFound
	// One bubble for a call run twice: the block relates to a consumed bubble as its consumer did.
	matchRepeat
	// The evidence reads as a deduped re-run and as an argument-less second run, and attaching is wrong
	// under one of them. Nothing is attached; the returned index is the undecided bubble.
	matchAmbiguous
)

// matchBlock also returns the match's evidence, which the caller records for repeat detection.
func matchBlock(blk block, role string, events []*bubble, cursor int, state []bubbleState) (int, matchOutcome, evidence, int) {
	wantType := 2
	if role == "user" {
		wantType = 1
	}

	// The second value is argsEvidence's strength; text has no gradation, so its positives carry 1.
	weigh := func(b *bubble) (evidence, int) {
		if b.Type != 0 && b.Type != wantType {
			return evidenceNegative, 0
		}
		switch blk.Type {
		case "tool_use":
			if b.ToolFormerData == nil {
				return evidenceNegative, 0
			}
			// Arguments, not names: the names differ, and arguments tell same-tool calls apart.
			return argsEvidence(blk.Input, b.ToolFormerData)

		case "text":
			if b.ToolFormerData != nil {
				return evidenceNegative, 0
			}
			// Reasoning needs real overlap, else an empty text block would consume it.
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

	// Of two full agreements the one agreeing on MORE is the call; position breaks ties. Lesser
	// grades wait for both scans, as a partial identifies only when unique; names count only where
	// position is the whole claim.
	bestPos, bestPosN := -1, 0
	partials := 0
	fwdPartial, fwdNeutral, fwdWeak := -1, -1, -1
	for i := cursor; i < len(events) && i < cursor+lookAhead; i++ {
		// Consuming always advances the cursor past the bubble, so no used check.
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

	// Look-behind: header and block order can disagree in a turn. Full agreement is the call wherever
	// it sits; on lesser grades a forward candidate wins, as one behind was already passed over.
	repeat := false
	repeatEv, repeatN := evidenceNegative, 0
	bhdPartial, bhdNeutral, bhdWeak := -1, -1, -1
	for i := cursor - 1; i >= 0; i-- {
		if state[i].used {
			// A consumed bubble testifies only to a block relating to it exactly as its consumer
			// did: a better claimant is the real owner after a positional fallback took it, a
			// worse one a different call. Unbounded: nothing is consumed here.
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
			// No positional look-behind for prose: far weaker than an argument-less call.
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

	// A lone partial wins: only it carries that value. Plural ones (sibling greps share the
	// workspace path) pool with the neutrals, forward first; weak comes last, its values
	// half-belonging to another call.
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
		// Dedup is refuted by an unconsumed full agreement anywhere (the run WAS recorded), loses
		// to a candidate as good as the consumed bubble (edit_file_v2 records only the path: edits
		// to one file would all repeat), and is undecidable against one recording nothing, which
		// may be the second run itself.
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
		// A worse candidate would attach another call's result and take the bubble it needs.
		return -1, matchRepeat, evidenceNegative, 0
	}
	if best >= 0 {
		ev, n := weigh(events[best])
		return best, matchFound, ev, n
	}
	return -1, matchNone, evidenceNegative, 0
}

// strictOverlap is textOverlap where an empty side is a non-match, never a free pass.
func strictOverlap(transcript, stored string) bool { return overlap(transcript, stored, false) }

// textOverlap ignores the transcript's wrapper tags, which the store lacks. An empty side cannot
// contradict: position in the ordered list stands.
func textOverlap(transcript, stored string) bool { return overlap(transcript, stored, true) }

func overlap(transcript, stored string, emptyMatches bool) bool {
	t := normaliseText(transcript)
	s := normaliseText(stored)
	if t == "" || s == "" {
		return emptyMatches
	}
	if strings.Contains(t, s) || strings.Contains(s, t) {
		return true
	}
	// Compare a prefix: the store truncates long prose in some generations.
	n := min(len(t), len(s), 64)
	return t[:n] == s[:n]
}

func normaliseText(s string) string {
	for _, tag := range []string{"timestamp", "user_query"} {
		s = stripTag(s, tag)
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimSpace(s)
}

func stripTag(s, tag string) string {
	open, close := "<"+tag+">", "</"+tag+">"
	for {
		i := strings.Index(s, open)
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], close)
		if j < 0 {
			return s[:i]
		}
		inner := s[i+len(open) : i+j]
		if tag == "user_query" {
			// The query IS the prose. Keep the contents, drop the tags.
			s = s[:i] + inner + s[i+j+len(close):]
		} else {
			s = s[:i] + s[i+j+len(close):]
		}
	}
}

// isRedactedReasoning matches the literal placeholder Cursor writes instead of reasoning.
func isRedactedReasoning(text string) bool {
	return strings.TrimSpace(text) == "[REDACTED]"
}

func fromBubble(b *bubble) *blockEnrich {
	model := b.ModelName
	if model == "" && b.ModelInfo != nil {
		model = b.ModelInfo.ModelName
	}
	e := &blockEnrich{
		BubbleID:       b.BubbleID,
		CreatedAt:      b.CreatedAt,
		RequestID:      b.RequestID,
		CheckpointID:   b.CheckpointID,
		TurnDurationMs: b.TurnDurationMs,
		ModelName:      model,
	}
	if t := b.ToolFormerData; t != nil {
		e.ToolCallID = t.ToolCallID
		e.ToolName = cmp.Or(t.Name, string(t.Tool))
		e.Status = t.Status
		e.Result = t.Result
	}
	return e
}

// No HTML escaping: the output hash is the change signal and must not depend on < > & in the input.
func writeLine(w *bytes.Buffer, l outLine) error {
	body, err := marshalCompact(l)
	if err != nil {
		return err
	}
	w.Write(body)
	w.WriteByte('\n')
	return nil
}

func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
