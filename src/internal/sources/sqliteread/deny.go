package sqliteread

import (
	"encoding/json"
	"slices"
	"strings"
)

// The compiled key/field deny, not configurable at any layer. Auth material lives inside the SAME database as
// the trajectories, and a path deny list cannot express "this file, minus these rows", so the exclusion has to
// happen at the row and field level, inside the read itself.

// deniedKeyPrefixes are keyspaces no enricher may read: cursorAuth/* holds Cursor's own session tokens.
var deniedKeyPrefixes = []string{"cursorauth/", "cursorauth."}

// deniedFields are stripped from every value at any depth: Cursor's blob keys, stored beside the content they protect.
var deniedFields = []string{"blobEncryptionKey", "speculativeSummarizationEncryptionKey"}

// allowedExactKeys are the compiled exceptions to the prefix deny. EXACT keys only: a prefix would ship the next key Cursor adds.
var allowedExactKeys = map[string]bool{
	"cursorauth/stripemembershiptype": true, // the plan (free/pro/business/enterprise)
	"cursorauth/cachedemail":          true, // which account the plan belongs to
	"cursorauth/cachedsignuptype":     true, // how the account authenticates (Google, ...)
	"cursorauth/cachedteam":           true, // {teamId, name}, no credential material
}

// keyDenied is case-insensitive: the namespace is spelled more than one way.
func keyDenied(key string) bool {
	lower := strings.ToLower(key)
	return !allowedExactKeys[lower] && slices.ContainsFunc(deniedKeyPrefixes, func(p string) bool {
		return strings.HasPrefix(lower, p)
	})
}

// scrubValue removes denied fields at any depth; a value that is not JSON has no fields to strip.
func scrubValue(raw []byte) ([]byte, int) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw, 0
	}
	// Verbatim when nothing was stripped: re-marshalling reorders keys.
	n := stripFields(v)
	if n == 0 {
		return raw, 0
	}
	out, _ := json.Marshal(v) // cannot fail on a value json.Unmarshal produced
	return out, n
}

// stripFields deletes in place; maps and slices share their backing storage with v.
func stripFields(v any) int {
	removed := 0
	switch t := v.(type) {
	case map[string]any:
		for _, f := range deniedFields {
			if _, ok := t[f]; ok {
				delete(t, f)
				removed++
			}
		}
		for _, child := range t {
			removed += stripFields(child)
		}
	case []any:
		for _, child := range t {
			removed += stripFields(child)
		}
	}
	return removed
}
