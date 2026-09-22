// store.go decodes the vendor row shapes of both generations a live state.vscdb holds into each
// conversation's event list. Structs decode only what the join reads: rows reach megabytes.

package cursorjoin

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources/sqliteread"
)

type composerData struct {
	// The newer generation's authoritative bubble order, which the inline array does not carry.
	FullConversationHeadersOnly []struct {
		BubbleID string `json:"bubbleId"`
	} `json:"fullConversationHeadersOnly"`

	// The older generation's inline array, empty on newer conversations.
	Conversation []bubble `json:"conversation"`
}

type bubble struct {
	BubbleID  string `json:"bubbleId"`
	Type      int    `json:"type"` // 1 = user, 2 = assistant
	Text      string `json:"text"`
	CreatedAt string `json:"createdAt"`
	RequestID string `json:"requestId"`

	// Current stores stamp capabilityType 15 on every tool bubble, so see isScaffolding.
	IsCapabilityIteration bool       `json:"isCapabilityIteration"`
	CapabilityType        flexString `json:"capabilityType"`

	// Older stores mark reasoning with isThought, current ones write a thinking object.
	IsThought bool          `json:"isThought"`
	Thinking  *thinkingData `json:"thinking"`

	ToolFormerData *toolFormerData `json:"toolFormerData"`

	CheckpointID   string `json:"checkpointId"`
	TurnDurationMs int64  `json:"turnDurationMs"`

	// ModelName is the older stores' field; current ones nest it as modelInfo.modelName.
	ModelName string `json:"modelName"`
	ModelInfo *struct {
		ModelName string `json:"modelName"`
	} `json:"modelInfo"`
}

// thinkingData decodes reasoning as an object, or as one serialised into a string on server-hydrated rows.
type thinkingData struct {
	Text string `json:"text"`
}

func (t *thinkingData) UnmarshalJSON(b []byte) error {
	type plain thinkingData // does not re-enter this method
	var s string
	if json.Unmarshal(b, &s) != nil {
		return json.Unmarshal(b, (*plain)(t))
	}
	// A string with no text under the known name is taken as the reasoning itself.
	if json.Unmarshal([]byte(s), (*plain)(t)) != nil || t.Text == "" {
		t.Text = s
	}
	return nil
}

func (b *bubble) reasoningText() string {
	if b.Thinking != nil && b.Thinking.Text != "" {
		return b.Thinking.Text
	}
	if b.IsThought {
		return b.Text
	}
	return ""
}

// flexString keeps a non-string's raw JSON text: the store migrated fields to numeric enums.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	if json.Unmarshal(b, (*string)(f)) != nil {
		*f = flexString(b)
	}
	return nil
}

// toolFormerData is the tool call as the store records it; Tool is a string in older stores, an enum now.
type toolFormerData struct {
	ToolCallID string     `json:"toolCallId"`
	Name       string     `json:"name"`
	Tool       flexString `json:"tool"`
	Status     string     `json:"status"`
	RawArgs    string     `json:"rawArgs"`
	Params     string     `json:"params"`
	Result     string     `json:"result"`
}

type indexed struct {
	composers map[string]*composerData
	bubbles   map[string]map[string]*bubble // conversation -> bubbleId -> bubble
	order     map[string][]*bubble          // conversation -> bubbles in key order

	// Surfaced as a note: silence turns struct drift into a mismatch alarm pointing elsewhere.
	decodeErrors int
}

func indexRows(rows []sqliteread.Row) *indexed {
	ix := &indexed{composers: map[string]*composerData{}, bubbles: map[string]map[string]*bubble{}, order: map[string][]*bubble{}}
	for _, r := range rows {
		if id, ok := strings.CutPrefix(r.Key, composerPrefix); ok {
			var c composerData
			if json.Unmarshal(r.Value, &c) != nil {
				ix.decodeErrors++
			} else {
				ix.composers[id] = &c
			}
			continue
		}
		rest, ok := strings.CutPrefix(r.Key, bubblePrefix)
		if !ok {
			continue // SQLite's LIKE ignores case; the prefixes do not
		}
		conv, bubbleID, ok := strings.Cut(rest, ":") // bubbleId:<conversation>:<bubble>
		var b bubble
		if !ok || json.Unmarshal(r.Value, &b) != nil {
			ix.decodeErrors++
			continue
		}
		b.BubbleID = cmp.Or(b.BubbleID, bubbleID)
		if ix.bubbles[conv] == nil {
			ix.bubbles[conv] = map[string]*bubble{}
		}
		ix.bubbles[conv][bubbleID] = &b
		ix.order[conv] = append(ix.order[conv], &b)
	}
	return ix
}

// orderBubbles takes the recorded header order, then the inline array, then a key scan (errored turns).
func orderBubbles(c *composerData, bubbles map[string]*bubble, keyOrder []*bubble) []*bubble {
	var out []*bubble
	if c != nil {
		for _, h := range c.FullConversationHeadersOnly {
			// A header naming an absent row is normal after compaction.
			if b, ok := bubbles[h.BubbleID]; ok {
				out = append(out, b)
			}
		}
		if len(out) > 0 {
			return out
		}
		for i := range c.Conversation {
			out = append(out, &c.Conversation[i])
		}
		if len(out) > 0 {
			return out
		}
	}
	// createdAt is a real timestamp, unlike anything in the transcript; ties keep key order.
	out = slices.Clone(keyOrder)
	slices.SortStableFunc(out, func(a, b *bubble) int { return cmp.Compare(a.CreatedAt, b.CreatedAt) })
	return out
}

// isScaffolding reports a bubble with no transcript counterpart by design; tool calls and reasoning never are.
func isScaffolding(b *bubble) bool {
	if b.ToolFormerData != nil || b.reasoningText() != "" {
		return false
	}
	return b.IsCapabilityIteration || b.CapabilityType != "" || b.Text == ""
}
