package cursorjoin

import (
	"bytes"
	"cmp"
	"encoding/json"
)

// line is one JSONL record, decoded only as far as the join needs. Scalars are flexString for
// the same reason as on the store side: a drifted field shape would reject the whole line, which
// then ships as native_invalid with its bubbles skipped and mismatches at zero — silent loss.
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

// outLine is one line of the derived JSONL. Native holds the original line's bytes verbatim, so
// no part of the native record depends on this code. Enrich is an array index-aligned to the
// native content blocks, never a map: a map's key order is lexicographic, so block 10 would sort
// before block 2 and the output bytes would stop being a stable function of the input.
type outLine struct {
	Native json.RawMessage `json:"native,omitempty"`

	// A line that is not valid JSON, carried as a string rather than dropped: a torn tail is
	// expected, and an invalid raw value would make the whole derived document unmarshalable.
	// Not byte-exact for a mid-rune tear, whose dangling bytes become U+FFFD — the byte-exact
	// record is the raw transcript, which ships anyway.
	NativeInvalid string `json:"native_invalid,omitempty"`

	Enrich []*blockEnrich `json:"_enrich,omitempty"`
}

// blockEnrich is what the store knew and the transcript did not.
type blockEnrich struct {
	BubbleID string `json:"bubbleId,omitempty"`

	// The correlation key the transcript is missing entirely.
	ToolCallID string `json:"tool_call_id,omitempty"`

	// ToolName is the INTERNAL name, which can differ from the transcript's display name.
	ToolName string `json:"tool_name,omitempty"`
	Status   string `json:"status,omitempty"`

	// The full tool output, which the transcript has none of.
	Result string `json:"result,omitempty"`

	CreatedAt      string `json:"createdAt,omitempty"`
	RequestID      string `json:"requestId,omitempty"`
	CheckpointID   string `json:"checkpointId,omitempty"`
	TurnDurationMs int64  `json:"turnDurationMs,omitempty"`
	ModelName      string `json:"modelName,omitempty"`
}

// alignAndRender walks the transcript and the ordered bubbles together, one pass over each,
// advancing the bubble cursor only on a match. The transcript is the authority on what happened,
// so an event it contains that the store cannot account for is a mismatch, while a store bubble
// the transcript does not mention is simply skipped. Three exceptions ship native-only and are
// counted apart: tail (the store ends before the transcript, as with injected turns), repeats
// (one bubble for a call the agent ran twice) and ambiguous (see matchAmbiguous).
func alignAndRender(content []byte, events []*bubble) (alignment, error) {
	var out bytes.Buffer
	cursor := 0

	// Unmatched blocks are classified once the pass completes, by where the last CONSUMING
	// match landed. Repeats and ambiguous events move no watermark, and a hole before one is
	// still caught by any real match after it.
	seq := 0
	lastMatchedSeq := -1
	var unmatched []int
	repeats := 0
	ambiguous := 0

	state := make([]bubbleState, len(events))

	// Decode failures are positioned, not just counted: only the final line's can be the
	// expected torn tail, and a mid-file one loses its blocks' enrichment with mismatches at zero.
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

		// turn_ended is a terminator, not an event. It has no bubble and must not consume
		// the cursor.
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
				// Explained, but nothing to attach: the consumed bubble's result
				// belongs to the run that consumed it.
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

// alignment is one conversation's alignment outcome: the rendered lines, the events nothing
// accounts for, and the explained shortfalls that ship native-only.
type alignment struct {
	out        []byte
	mismatches int
	tail       int
	repeats    int

	// Tool blocks the evidence could not decide; nothing is attached to them.
	ambiguous int

	// Transcript lines that did not decode, excluding the final line's vendor-confirmed torn
	// tail. Surfaced by the caller the way indexed.decodeErrors is.
	lineDecodeErrors int
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

// writeLine emits one output record. No HTML escaping: the output hash is the change signal, and
// json.Encoder's default < > & escaping would make it depend on the transcript's punctuation.
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
	// Encode appends a newline; writeLine adds its own, so trim this one.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
