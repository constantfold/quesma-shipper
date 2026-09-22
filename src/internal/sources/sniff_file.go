package sources

import (
	"bytes"
	"encoding/hex"
	"os"

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
