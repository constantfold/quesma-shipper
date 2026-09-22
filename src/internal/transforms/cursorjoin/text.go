package cursorjoin

import "strings"

// textEvidence treats an empty side as positional evidence; matching prose confirms identity.
func textEvidence(transcript, stored string) (evidence, int) {
	t, s := normaliseText(transcript), normaliseText(stored)
	if t == "" || s == "" {
		return evidenceNeutral, 0
	}
	// Some store generations truncate prose, so a shared prefix still confirms it.
	n := min(len(t), len(s), 64)
	if strings.Contains(t, s) || strings.Contains(s, t) || t[:n] == s[:n] {
		return evidencePositive, 1
	}
	return evidenceNegative, 0
}

// normaliseText strips the transcript's wrapper tags, which the store side does not have. The
// query is the prose, so user_query keeps its contents.
func normaliseText(s string) string {
	s = stripTag(s, "timestamp", false)
	s = stripTag(s, "user_query", true)
	return strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
}

func stripTag(s, tag string, keepInner bool) string {
	for {
		before, rest, ok := strings.Cut(s, "<"+tag+">")
		if !ok {
			return s
		}
		inner, after, ok := strings.Cut(rest, "</"+tag+">")
		if !ok {
			return before
		}
		if keepInner {
			before += inner
		}
		s = before + after
	}
}

// isRedactedReasoning matches the literal placeholder Cursor writes instead of reasoning.
func isRedactedReasoning(text string) bool { return strings.TrimSpace(text) == "[REDACTED]" }
