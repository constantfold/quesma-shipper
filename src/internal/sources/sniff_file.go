package sources

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// sniff runs the catalog's shape assertion: shape, never semantics, so a drifted format is a data fix rather than a release.
func sniff(path string, spec *Sniff) (formats.SniffResult, string) {
	if spec == nil || spec.Kind == "" || spec.Kind == "none" {
		return formats.SniffOK, ""
	}

	head, info, err := readHead(path, spec.MaxScanBytes)
	if err != nil {
		return formats.SniffUnreadable, ""
	}
	if len(head) == 0 {
		return formats.SniffEmpty, ""
	}
	truncated := info != nil && info.Size() > int64(len(head))

	switch spec.Kind {
	case "jsonl":
		return sniffJSONL(head, truncated)
	case "json":
		if body := bytes.TrimLeft(head, " \t\n\r"); len(body) == 0 || (body[0] != '{' && body[0] != '[') {
			return formats.SniffUnexpectedShape, ""
		}
	case "magic":
		want, err := hex.DecodeString(spec.MagicHex)
		if err != nil || !bytes.HasPrefix(head, want) {
			return formats.SniffUnexpectedShape, ""
		}
	case "text":
		if bytes.IndexByte(head, 0) >= 0 {
			return formats.SniffUnexpectedShape, ""
		}
	}
	return formats.SniffOK, ""
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

// sniffSampleSize is how many files are asked before condemning a source.
const sniffSampleSize = 5

// sniffSample deterministically asks files spread across the ordering, first and last included, so a source cannot oscillate.
func sniffSample(matched []Candidate, spec *Sniff) (formats.SniffResult, string, int) {
	var best formats.SniffResult
	failures, version := 0, ""
	// Count every failure; the version comes from the newest readable file, the closest proxy for the current install.
	for i := range min(len(matched), sniffSampleSize) {
		at := i
		if len(matched) > sniffSampleSize {
			at = i * (len(matched) - 1) / (sniffSampleSize - 1)
		}
		result, agentVersion := sniff(matched[at].Path, spec)
		if result == formats.SniffUnreadable || result == formats.SniffUnexpectedShape {
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

// sniffJSONL asserts the first non-empty line parses as JSON, and opportunistically reads the producer version out of the head.
func sniffJSONL(head []byte, truncated bool) (formats.SniffResult, string) {
	// A NUL byte settles it: no JSONL store contains one, so this store became binary.
	if bytes.IndexByte(head, 0) >= 0 {
		return formats.SniffUnexpectedShape, ""
	}

	line, _, terminated := bytes.Cut(head, []byte{'\n'})
	// "No newline" means two things: a truncated head simply ran past the scan budget, a whole file with none is real drift.
	unjudgeable := !terminated && truncated

	blank := len(bytes.TrimSpace(line)) == 0
	var rec map[string]json.RawMessage
	switch {
	case !blank && json.Unmarshal(line, &rec) == nil:
		return formats.SniffOK, versionFromHead(head)
	case unjudgeable:
		return formats.SniffOK, ""
	case blank:
		return formats.SniffEmpty, ""
	}
	return formats.SniffUnexpectedShape, ""
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
