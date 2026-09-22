package sources

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// sniff runs the catalog's shape assertion: shape, never semantics, so a drifted format is a data fix rather than a release.
func sniff(path string, spec *Sniff) (SniffResult, string) {
	if spec == nil || spec.Kind == "" || spec.Kind == "none" {
		return SniffOK, ""
	}

	head, info, err := readHead(path, spec.MaxScanBytes)
	if err != nil {
		return SniffUnreadable, ""
	}
	if len(head) == 0 {
		return SniffEmpty, ""
	}
	// Whether the head stopped at the budget or at end of file changes what a missing newline means.
	truncated := info != nil && info.Size() > int64(len(head))

	switch spec.Kind {
	case "jsonl":
		return sniffJSONL(head, truncated)
	case "json":
		if body := bytes.TrimLeft(head, " \t\n\r"); len(body) == 0 || (body[0] != '{' && body[0] != '[') {
			return SniffUnexpectedShape, ""
		}
	case "magic":
		want, err := hex.DecodeString(spec.MagicHex)
		if err != nil || !bytes.HasPrefix(head, want) {
			return SniffUnexpectedShape, ""
		}
	case "text":
		if bytes.IndexByte(head, 0) >= 0 {
			return SniffUnexpectedShape, ""
		}
	}
	return SniffOK, ""
}

// readHead reads up to budget bytes, 64 KiB when budget is not positive.
func readHead(path string, budget int64) ([]byte, os.FileInfo, error) {
	if budget <= 0 {
		budget = 64 << 10
	}
	f, info, err := platform.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	if info.Size() == 0 {
		return nil, info, nil
	}
	buf := make([]byte, min(budget, info.Size()))
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, info, err
	}
	return buf[:n], info, nil
}

// sniffSampleSize is how many files are asked before condemning a source, spread across the ordering rather than taken from one end.
const sniffSampleSize = 5

// sniffSample asks several files and returns the best answer. Deterministic: a source must not oscillate across ticks.
func sniffSample(matched []Candidate, spec *Sniff) (SniffResult, string, int) {
	if len(matched) == 0 {
		return SniffUnreadable, "", 0
	}
	idx := sampleIndexes(len(matched), sniffSampleSize)

	var best SniffResult
	failures, version := 0, ""
	// Scan the whole sample so every unreadable file is counted, and take the version from the
	// newest readable one (idx ascends by mtime): the closest proxy for the current install.
	for i, at := range idx {
		result, agentVersion := sniff(matched[at].Path, spec)
		if result == SniffUnreadable || result == SniffUnexpectedShape {
			failures++
			if i == 0 {
				best = result
			}
			continue
		}
		best, version = result, agentVersion
	}
	return best, version, failures
}

// sampleIndexes picks up to n positions spread evenly across length, always including the first and the last.
func sampleIndexes(length, n int) []int {
	out := make([]int, min(length, n))
	for i := range out {
		out[i] = i
		if length > n {
			out[i] = i * (length - 1) / (n - 1)
		}
	}
	return out
}

// sniffJSONL asserts the first non-empty line parses as JSON, and opportunistically reads the producer version out of the head.
func sniffJSONL(head []byte, truncated bool) (SniffResult, string) {
	// A NUL byte settles it: no JSONL store contains one, so this store became binary.
	if bytes.IndexByte(head, 0) >= 0 {
		return SniffUnexpectedShape, ""
	}

	line, terminated := firstLine(head)

	// "No newline" means two things: a truncated head simply ran past the scan budget, a whole file with none is real drift.
	unjudgeable := !terminated && truncated

	if strings.TrimSpace(line) == "" {
		if unjudgeable {
			return SniffOK, ""
		}
		return SniffEmpty, ""
	}

	var rec map[string]json.RawMessage
	if json.Unmarshal([]byte(line), &rec) != nil {
		if unjudgeable {
			return SniffOK, ""
		}
		return SniffUnexpectedShape, ""
	}
	return SniffOK, versionFromHead(head)
}

// The version rides a header line that is not always the first: the first line plus sixteen more.
const maxVersionScanLines = 17

func versionFromHead(head []byte) string {
	scanned := 0
	for line := range bytes.Lines(head) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if scanned++; scanned > maxVersionScanLines {
			break
		}
		var rec map[string]json.RawMessage
		if json.Unmarshal(line, &rec) == nil {
			if v := versionFrom(rec); v != "" {
				return v
			}
		}
	}
	return ""
}

// versionFrom looks for a producer version under the field names the surveyed stores actually use.
func versionFrom(rec map[string]json.RawMessage) string {
	for _, field := range []string{"version", "cli_version"} {
		if value := lookupField(rec, field); value != "" {
			return value
		}
	}
	// Codex nests it one level down.
	if raw, ok := rec["payload"]; ok {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(raw, &nested); err == nil {
			return versionFrom(nested)
		}
	}
	return ""
}

// firstLine returns the first line and whether a terminator was seen: a line cut off by the budget is not malformed.
func firstLine(head []byte) (string, bool) {
	if line, _, found := bytes.Cut(head, []byte{'\n'}); found {
		return string(bytes.TrimRight(line, "\r")), true
	}
	return string(head), false
}
