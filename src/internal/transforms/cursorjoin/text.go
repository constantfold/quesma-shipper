package cursorjoin

import (
	"strings"
)

// strictOverlap reports whether two texts genuinely share their prose. Stricter than
// textOverlap on purpose: an empty side is a non-match here, never a free pass.
func strictOverlap(transcript, stored string) bool { return overlap(transcript, stored, false) }

// textOverlap reports whether a transcript text block and a bubble carry the same prose. The
// transcript wraps user text in tags the store does not, so a normalised core is compared.
// An empty side cannot contradict: position in the ordered list stands.
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
