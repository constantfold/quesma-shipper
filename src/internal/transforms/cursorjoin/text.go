package cursorjoin

import (
	"strings"
)

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

func normaliseText(s string) string {
	// Strip the transcript's wrapper tags, which the store side does not have.
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
