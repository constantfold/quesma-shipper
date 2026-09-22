//go:build perf

// Deterministic, incompressible fixtures for the large-file memory scenarios, streamed to disk:
// an in-memory copy would make the harness the largest measured process.
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

const (
	// 64 symbols, so one random byte masked to six bits picks one.
	memguardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	// Break runs before the entropy detector's 24-character minimum.
	memguardRun = 20

	// Large enough that the JSON frame is noise, small enough that generating a file stays a stream.
	memguardLineFill = 8 << 10

	singleLineChunk = 390 * (memguardRun + 1)
)

// A transcript under slug and the call that commits it. bufio write errors are sticky, so the loops
// check one write each and Flush reports the rest.
func createFixture(t *testing.T, w *world, slug, session string) (bw *bufio.Writer, cwd string, finish func()) {
	t.Helper()
	cwd = "/Users/perf/work/" + strings.TrimPrefix(slug, "-Users-perf-work-")
	path := filepath.Join(w.Home, ".claude", "projects", slug, session+".jsonl")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	bw = bufio.NewWriterSize(f, 1<<20)
	return bw, cwd, func() {
		require.NoErrorf(t, bw.Flush(), "write %s", path)
		require.NoErrorf(t, f.Close(), "close %s", path)
		// The pre-filter compares size and mtime, so the stamp cannot be the wall clock.
		require.NoError(t, os.Chtimes(path, fixtureMTime, fixtureMTime))
	}
}

// One line per memguardLineFill of fill; every secretEvery-th (none if zero) also carries two secrets.
func stageIncompressibleFile(t *testing.T, w *world, index int, target int64, secretEvery int) (int, int) {
	t.Helper()
	session := corpusSessionID(index)
	bw, cwd, finish := createFixture(t, w, fmt.Sprintf("-Users-perf-work-bulk-%d", index), session)
	written, _ := fmt.Fprintf(bw, corpusFirstLine, session, cwd)

	src := rand.NewChaCha8(memguardStreamSeed(index))
	fill := make([]byte, memguardLineFill)
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
		require.NoError(t, err) // sticky, and a writer that stopped growing would loop forever
		written += n
	}
	finish()
	return written, secretLines
}

// The whole target in one JSON string; a non-empty secret precedes every chunk of fill.
func stageSingleLineFile(t *testing.T, w *world, slug string, target int64, secret string) (int, int) {
	t.Helper()
	session := corpusSessionID(0)
	bw, cwd, finish := createFixture(t, w, slug, session)

	tail := `"}],"usage":{"input_tokens":120,"output_tokens":340}}}` + "\n"
	written, _ := fmt.Fprintf(bw, `{"type":"assistant","uuid":"a1","sessionId":%q,"cwd":%q,"message":{"id":"m1","model":"claude-opus-5","content":[{"type":"text","text":"`, session, cwd)
	src := rand.NewChaCha8(memguardStreamSeed(0))
	fill := make([]byte, singleLineChunk)
	secrets := 0
	for int64(written+len(tail)) < target {
		if secret != "" {
			n, _ := bw.WriteString(secret + " ")
			written += n
			secrets++
		}
		memguardFill(t, src, fill)
		n, err := bw.Write(fill)
		require.NoError(t, err)
		written += n
	}
	n, _ := bw.WriteString(tail)
	finish()
	return written + n, secrets
}

// Different files need different content so storage deduplication cannot make the test cheap.
func memguardStreamSeed(index int) [32]byte {
	seed := [32]byte([]byte(memguardSeedText))
	seed[len(seed)-1] ^= byte(index)
	seed[len(seed)-2] ^= byte(index >> 8)
	return seed
}

// Break high-entropy text into runs shorter than the entropy detector accepts.
func memguardFill(t *testing.T, src *rand.ChaCha8, buf []byte) {
	t.Helper()
	_, err := src.Read(buf)
	require.NoError(t, err, "read the fixture stream")
	for i := range buf {
		if i%(memguardRun+1) == memguardRun {
			buf[i] = ' '
		} else {
			buf[i] = memguardAlphabet[buf[i]&63]
		}
	}
}
