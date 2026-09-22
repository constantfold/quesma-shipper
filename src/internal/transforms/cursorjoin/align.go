package cursorjoin

import (
	"bytes"
	"cmp"
	"encoding/json"
)

// line is one JSONL record, decoded as far as the join needs; flexString keeps a drifted line enrichable.
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

// outLine is the original line verbatim (a string when not valid JSON) plus enrichments index-aligned to its blocks.
type outLine struct {
	Native        json.RawMessage `json:"native,omitempty"`
	NativeInvalid string          `json:"native_invalid,omitempty"`
	Enrich        []*blockEnrich  `json:"_enrich,omitempty"`
}

// blockEnrich is what the store knew and the transcript did not.
type blockEnrich struct {
	BubbleID   string `json:"bubbleId,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	ToolName   string `json:"tool_name,omitempty"` // the internal name, not the display name
	Status     string `json:"status,omitempty"`
	Result     string `json:"result,omitempty"`

	CreatedAt      string `json:"createdAt,omitempty"`
	RequestID      string `json:"requestId,omitempty"`
	CheckpointID   string `json:"checkpointId,omitempty"`
	TurnDurationMs int64  `json:"turnDurationMs,omitempty"`
	ModelName      string `json:"modelName,omitempty"`
}

// alignAndRender walks transcript and bubbles together; the transcript is the authority on what is a mismatch.
func alignAndRender(content []byte, events []*bubble) (alignment, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false) // Punctuation must not change the derived output hash.
	var a alignment
	state := make([]bubbleState, len(events))
	// A consuming match turns all preceding unmatched blocks into gaps; only the remainder can be tail.
	cursor, unmatched, lastLineInvalid := 0, 0, false

	for raw := range bytes.SplitSeq(content, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			continue
		}
		record := outLine{Native: trimmed}
		var l line
		err := json.Unmarshal(trimmed, &l)
		// A truncated tail is expected: Cursor's transcript writes are not atomic.
		lastLineInvalid = err != nil
		if err != nil {
			a.lineDecodeErrors++
			record = outLine{NativeInvalid: string(trimmed)}
		} else if l.Role != "" && l.Message != nil {
			for i, blk := range l.Message.Content {
				// Reasoning arrives as a literal [REDACTED] with nothing to align to.
				if blk.Type == "text" && isRedactedReasoning(string(blk.Text)) {
					continue
				}
				idx, outcome, ev, n := matchBlock(blk, string(l.Role), events, cursor, state)
				switch outcome {
				case matchNone:
					unmatched++
					continue
				case matchRepeat:
					// Nothing to attach: the consumed bubble's result belongs to the other run.
					a.repeats++
					continue
				case matchAmbiguous:
					a.ambiguous++
					state[idx].declined = true
					continue
				}
				a.mismatches += unmatched
				unmatched = 0
				state[idx].used, state[idx].ev, state[idx].n = true, ev, n
				cursor = max(cursor, idx+1)
				if record.Enrich == nil {
					record.Enrich = make([]*blockEnrich, len(l.Message.Content))
				}
				record.Enrich[i] = fromBubble(events[idx])
			}
		}
		if err := encoder.Encode(record); err != nil {
			return alignment{}, err
		}
	}

	a.out = out.Bytes()
	// A decode failure is an expected torn tail only when it is the final nonempty line.
	if lastLineInvalid {
		a.lineDecodeErrors--
	}
	// A transcript that matched nothing is all mismatch, not all tail.
	if cursor > 0 {
		a.tail = unmatched
	} else {
		a.mismatches = unmatched
	}
	return a, nil
}

type alignment struct {
	out                                  []byte
	mismatches, tail, repeats, ambiguous int
	lineDecodeErrors                     int // excluding the final line's expected torn tail
}

func fromBubble(b *bubble) *blockEnrich {
	model := b.ModelName
	if b.ModelInfo != nil {
		model = cmp.Or(model, b.ModelInfo.ModelName)
	}
	e := &blockEnrich{BubbleID: b.BubbleID, CreatedAt: b.CreatedAt, RequestID: b.RequestID,
		CheckpointID: b.CheckpointID, TurnDurationMs: b.TurnDurationMs, ModelName: model}
	if t := b.ToolFormerData; t != nil {
		e.ToolCallID, e.ToolName, e.Status, e.Result = t.ToolCallID, cmp.Or(t.Name, string(t.Tool)), t.Status, t.Result
	}
	return e
}
