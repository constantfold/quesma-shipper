//go:build perf

// Deterministic, incompressible fixtures for the large-file memory scenarios.
package perf

import (
	"bufio"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A fixed seed makes runs comparable.
const memguardSeedText = "trajectory-shipper perf memguard"

// Exactly the 32 bytes ChaCha8 takes, checked while compiling: a longer seed truncates silently.
const (
	_ = uint(len(memguardSeedText) - 32)
	_ = uint(32 - len(memguardSeedText))
)

var memguardSeed = [32]byte([]byte(memguardSeedText))

const (
	// 64 symbols, so one random byte masked to six bits picks one.
	memguardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	// Break runs before the entropy detector's 24-character minimum.
	memguardRun = 20

	// Large enough that the JSON frame is noise, small enough that generating a file stays a stream.
	memguardLineFill = 8 << 10
)

func stageIncompressibleFile(t *testing.T, w *world, index int, target int64) int {
	t.Helper()
	written, _ := stageIncompressibleValue(t, w, index, target, 0)
	return written
}

// Stream the fixture; an in-memory copy would make the harness the largest measured process.
func stageIncompressibleValue(t *testing.T, w *world, index int, target int64, secretEvery int) (int, int) {
	t.Helper()
	slug := fmt.Sprintf("-Users-perf-work-bulk-%d", index)
	session := corpusSessionID(index)
	cwd := "/Users/perf/work/" + strings.TrimPrefix(slug, "-Users-perf-work-")
	path := filepath.Join(w.Home, ".claude", "projects", slug, session+".jsonl")

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	bw := bufio.NewWriterSize(f, 1<<20)

	written := 0
	n, err := fmt.Fprintf(bw, corpusFirstLine, session, cwd)
	require.Falsef(t, err != nil, "write %s: %v", path, err)
	written += n

	src := rand.NewChaCha8(memguardStreamSeed(index))
	fill := make([]byte, memguardLineFill)
	// Space-delimited bare secrets preserve filler alignment and avoid key-name rules or string-edge matches.
	secretTail := []byte(" " + corpusGitHubToken + " " + corpusAWSKey + " end of line")
	text := make([]byte, 0, memguardLineFill+len(secretTail))
	secretLines := 0
	for line := 1; int64(written) < target; line++ {
		memguardFill(t, src, fill)
		text = append(text[:0], fill...)
		if secretEvery > 0 && line%secretEvery == 0 {
			text = append(text, secretTail...)
			secretLines++
		}
		n, err := fmt.Fprintf(bw, `{"type":"assistant","uuid":"a%d","sessionId":%q,"cwd":%q,"message":{"id":"m%d","model":"claude-opus-5","content":[{"type":"text","text":%q}],"usage":{"input_tokens":120,"output_tokens":340}}}`+"\n",
			line, session, cwd, line, text)
		require.Falsef(t, err != nil, "write %s: %v", path, err)
		written += n
	}
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	// The pre-filter compares size and mtime, so the stamp cannot be the wall clock.
	require.NoError(t, os.Chtimes(path, fixtureMTime, fixtureMTime))
	return written, secretLines
}

const singleLineChunk = 390 * (memguardRun + 1)

func stageSingleLineFile(t *testing.T, w *world, target int64) int {
	t.Helper()
	written, _ := stageSingleLineValue(t, w, "-Users-perf-work-oneline", target, "")
	return written
}

func stageSingleLineSecretFile(t *testing.T, w *world, target int64) (int, int) {
	t.Helper()
	return stageSingleLineValue(t, w, "-Users-perf-work-oneline-secrets", target, corpusGitHubToken)
}

func stageSingleLineValue(t *testing.T, w *world, slug string, target int64, secret string) (int, int) {
	t.Helper()
	session := corpusSessionID(0)
	cwd := "/Users/perf/work/" + strings.TrimPrefix(slug, "-Users-perf-work-")
	path := filepath.Join(w.Home, ".claude", "projects", slug, session+".jsonl")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	bw := bufio.NewWriterSize(f, 1<<20)

	tail := `"}],"usage":{"input_tokens":120,"output_tokens":340}}}` + "\n"
	written, err := fmt.Fprintf(bw, `{"type":"assistant","uuid":"a1","sessionId":%q,"cwd":%q,"message":{"id":"m1","model":"claude-opus-5","content":[{"type":"text","text":"`, session, cwd)
	require.NoError(t, err)
	src := rand.NewChaCha8(memguardStreamSeed(0))
	fill := make([]byte, singleLineChunk)
	secrets := 0
	for int64(written+len(tail)) < target {
		if secret != "" {
			n, err := bw.WriteString(secret + " ")
			require.NoError(t, err)
			written += n
			secrets++
		}
		memguardFill(t, src, fill)
		n, err := bw.Write(fill)
		require.NoError(t, err)
		written += n
	}
	n, err := bw.WriteString(tail)
	require.NoError(t, err)
	written += n
	require.NoError(t, bw.Flush())
	require.NoError(t, f.Close())
	require.NoError(t, os.Chtimes(path, fixtureMTime, fixtureMTime))
	return written, secrets
}

// Different files need different content so storage deduplication cannot make the test cheap.
func memguardStreamSeed(index int) [32]byte {
	seed := memguardSeed
	seed[len(seed)-1] ^= byte(index)
	seed[len(seed)-2] ^= byte(index >> 8)
	return seed
}

// Break high-entropy text into runs shorter than the entropy detector accepts.
func memguardFill(t *testing.T, src *rand.ChaCha8, buf []byte) {
	t.Helper()
	if _, err := src.Read(buf); err != nil {
		t.Fatalf("read the fixture stream: %v", err)
	}
	for i := range buf {
		if i%(memguardRun+1) == memguardRun {
			buf[i] = ' '
			continue
		}
		buf[i] = memguardAlphabet[buf[i]&63]
	}
}
