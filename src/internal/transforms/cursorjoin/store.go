// store.go is the store side of the join: the vendor row shapes in the two generations a live
// state.vscdb holds, and the indexing and ordering that turn rows into a conversation's event
// list. Every struct decodes only what the join reads: rows reach megabytes, and no rows ship.

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

// thinkingData decodes reasoning in both encodings a store holds: an object, and that object
// serialised into a string on server-hydrated rows. A strict field would reject the whole row.
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

// reasoningText is a bubble's reasoning in either generation's encoding; empty means none.
func (b *bubble) reasoningText() string {
	if b.Thinking != nil && b.Thinking.Text != "" {
		return b.Thinking.Text
	}
	if b.IsThought {
		return b.Text
	}
	return ""
}

// flexString decodes any JSON value as a string, keeping a non-string's raw JSON text: the store
// migrated several fields to numeric enums, and a strict field rejects the whole row.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	if json.Unmarshal(b, (*string)(f)) != nil {
		*f = flexString(b)
	}
	return nil
}

// toolFormerData is the tool call as the store records it, including the result this enricher
// exists for. Tool is a string in older stores, a numeric enum in current.
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
			if err := json.Unmarshal(r.Value, &c); err != nil {
				ix.decodeErrors++
				continue
			}
			ix.composers[id] = &c
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

// orderBubbles produces the authoritative bubble order: fullConversationHeadersOnly, the only
// place it is recorded, then a key scan for the errored turns whose header list is empty.
func orderBubbles(c *composerData, bubbles map[string]*bubble, keyOrder []*bubble) []*bubble {
	var out []*bubble
	if c != nil {
		for _, h := range c.FullConversationHeadersOnly {
			// A header naming an absent row is normal after compaction; skipping the gap is
			// what keeps a compacted conversation shipping.
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

// isScaffolding reports whether a bubble has no transcript counterpart by design. A tool call or
// reasoning bubble is an event whatever else it is flagged with; an unmentioned one goes unconsumed.
func isScaffolding(b *bubble) bool {
	if b.ToolFormerData != nil || b.reasoningText() != "" {
		return false
	}
	return b.IsCapabilityIteration || b.CapabilityType != "" || b.Text == ""
}
