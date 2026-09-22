package transforms

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// BenchmarkScrubSynthetic is the portable harness a change can be iterated against;
// BenchmarkScrubRealData measures the truth. Two shapes load different parts of the ladder:
// transcript-1MiB is many short lines, so per-line cost dominates, while bigvalue-8MiB is one
// line whose payload sits in a single string, so the per-value matchers do.
func BenchmarkScrubSynthetic(b *testing.B) {
	benchmarkSynthetic(b, syntheticTranscript(1<<20), syntheticBigValue(8<<20, 20260817, randCommandOutput))
}

func benchmarkSynthetic(b *testing.B, transcript, bigValue []byte) {
	cfg := DefaultConfig()
	cfg.Username = "devuser"
	s, err := New(cfg)
	require.NoError(b, err)

	cases := []struct {
		name    string
		payload []byte
	}{
		{"transcript-1MiB", transcript},
		{"bigvalue-8MiB", bigValue},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := s.Scrub(tc.payload, Hint{Family: "claude-code", JSONL: true})
				require.NoError(b, err)
				require.NotEqual(b, 0, len(res.Out), "empty output")
			}
		})
	}
}

// syntheticTranscript builds JSONL lines shaped like a Claude Code transcript, with planted
// secrets at roughly the density real transcripts show.
func syntheticTranscript(size int) []byte {
	rng := rand.New(rand.NewSource(20260816))
	var b strings.Builder
	b.Grow(size + 4096)
	encoder := json.NewEncoder(&b)

	for i := 0; b.Len() < size; i++ {
		var line map[string]any
		switch i % 5 {
		case 0, 2:
			line = map[string]any{
				"parentUuid":  randUUID(rng),
				"isSidechain": false,
				"userType":    "external",
				"cwd":         "/Users/devuser/git/trajectory-shipper",
				"sessionId":   randUUID(rng),
				"version":     "1.0.60",
				"type":        "assistant",
				"message": map[string]any{
					"id":      "msg_01" + randString(rng, tokenAlphabet, 22),
					"role":    "assistant",
					"model":   "claude-opus-4",
					"content": []any{map[string]any{"type": "text", "text": randProse(rng, 200+rng.Intn(600))}},
					"usage":   map[string]any{"input_tokens": 4211, "output_tokens": 118},
				},
				"uuid":      randUUID(rng),
				"timestamp": "2026-08-16T09:12:44.117Z",
			}
		case 1, 3:
			line = syntheticToolResult(rng, randCommandOutput)
		default:
			line = map[string]any{
				"parentUuid": randUUID(rng),
				"cwd":        "/Users/devuser/git/trajectory-shipper",
				"sessionId":  randUUID(rng),
				"type":       "user",
				"message":    map[string]any{"role": "user", "content": randProse(rng, 120+rng.Intn(300))},
				"uuid":       randUUID(rng),
				"timestamp":  "2026-08-16T09:12:46.551Z",
			}
			if i%37 == 0 {
				// Enough planted secrets to exercise the re-serialize path, without a file of secrets.
				line["message"].(map[string]any)["content"] =
					"export AWS_SECRET_ACCESS_KEY=" + randString(rng, tokenAlphabet, 40) + " && ./deploy.sh"
			}
		}
		if err := encoder.Encode(line); err != nil {
			panic(err)
		}
	}
	return []byte(b.String())
}

// syntheticBigValue is one record whose tool result holds the whole payload: the shape a
// spilled build log or a big file read takes.
func syntheticBigValue(size int, seed int64, output func(*rand.Rand, int) string) []byte {
	rng := rand.New(rand.NewSource(seed))
	body := output(rng, size)
	line, err := json.Marshal(map[string]any{
		"type":          "user",
		"uuid":          randUUID(rng),
		"sessionId":     randUUID(rng),
		"cwd":           "/Users/devuser/git/trajectory-shipper",
		"toolUseResult": map[string]any{"stdout": body, "stderr": "", "tool_use_id": "toolu_01" + randString(rng, tokenAlphabet, 22)},
		"timestamp":     "2026-08-16T09:13:02.900Z",
	})
	if err != nil {
		panic(err)
	}
	return append(line, '\n')
}

// Both corpora draw fields in the same order, preserving their seeded byte streams.
func syntheticToolResult(rng *rand.Rand, output func(*rand.Rand, int) string) map[string]any {
	return map[string]any{
		"parentUuid": randUUID(rng),
		"cwd":        "/Users/devuser/git/trajectory-shipper",
		"sessionId":  randUUID(rng),
		"type":       "user",
		"message": map[string]any{
			"role": "user",
			"content": []any{
				map[string]any{
					"type":        "tool_result",
					"tool_use_id": "toolu_01" + randString(rng, tokenAlphabet, 22),
					"content":     output(rng, 300+rng.Intn(900)),
				},
			},
		},
		"toolUseResult": map[string]any{
			"stdout":      output(rng, 200+rng.Intn(400)),
			"stderr":      "",
			"tool_use_id": "toolu_01" + randString(rng, tokenAlphabet, 22),
		},
		"uuid":      randUUID(rng),
		"timestamp": "2026-08-16T09:12:45.002Z",
	}
}

// BenchmarkScrubSyntheticAt is BenchmarkScrubSynthetic's corpus with '@' in it: the original has
// none, so the email rule (the most expensive pattern on real data) never fires there. A second
// benchmark rather than an edit to the first, whose numbers are the tracked series.
func BenchmarkScrubSyntheticAt(b *testing.B) {
	benchmarkSynthetic(b, syntheticTranscriptAt(1<<20), syntheticBigValue(8<<20, 20260819, randCommandOutputAt))
}

// randCommandOutputAt carries the '@' shapes tool output actually has: scoped package specs,
// decorators, doc tags, ssh targets, git author lines. Most are NOT emails, which is the point:
// the rule's cost is paid on every '@' and recovered only on the few that complete a match.
func randCommandOutputAt(rng *rand.Rand, n int) string {
	var sb strings.Builder
	sb.Grow(n + 128)
	for sb.Len() < n {
		switch rng.Intn(10) {
		case 0:
			fmt.Fprintf(&sb, "npm WARN deprecated @quesma/%s@%d.%d.%d: use @quesma/%s instead\n",
				proseWords[rng.Intn(len(proseWords))], rng.Intn(9), rng.Intn(20), rng.Intn(20),
				proseWords[rng.Intn(len(proseWords))])
		case 1:
			fmt.Fprintf(&sb, "commit %s\nAuthor: Dev User <devuser@example.com>\n", randString(rng, hexDigits, 40))
		case 2:
			fmt.Fprintf(&sb, "  @param {%s} %s - %s\n", proseWords[rng.Intn(len(proseWords))],
				proseWords[rng.Intn(len(proseWords))], randProse(rng, 40))
		case 3:
			fmt.Fprintf(&sb, "ssh devuser@build-%02d.internal.example: %s\n", rng.Intn(40),
				randProse(rng, 40))
		case 4:
			fmt.Fprintf(&sb, "@decorator(name=\"%s\")\ndef %s(self):\n", proseWords[rng.Intn(len(proseWords))],
				proseWords[rng.Intn(len(proseWords))])
		default:
			sb.WriteString(randCommandOutput(rng, 120+rng.Intn(240)))
		}
	}
	return sb.String()
}

func syntheticTranscriptAt(size int) []byte {
	rng := rand.New(rand.NewSource(20260818))
	var b strings.Builder
	b.Grow(size + 4096)
	encoder := json.NewEncoder(&b)

	for i := 0; b.Len() < size; i++ {
		line := syntheticToolResult(rng, randCommandOutputAt)
		if i%37 == 0 {
			line["message"].(map[string]any)["content"] =
				"export AWS_SECRET_ACCESS_KEY=" + randString(rng, tokenAlphabet, 40) + " && ./deploy.sh"
		}
		if err := encoder.Encode(line); err != nil {
			panic(err)
		}
	}
	return []byte(b.String())
}

const hexDigits = "0123456789abcdef"

func randUUID(rng *rand.Rand) string {
	hex := randString(rng, hexDigits, 32)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex[:8], hex[8:12], hex[12:16], hex[16:20], hex[20:])
}

const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randString(rng *rand.Rand, alphabet string, n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte(alphabet[rng.Intn(len(alphabet))])
	}
	return sb.String()
}

var proseWords = strings.Fields(`the scrubber walks every decoded string value and applies
the pattern packs before the entropy backstop so a false positive costs a placeholder and a
false negative costs a leak I will read the file first then run the tests and report what
changed the manifest records density per object so a rule that starts eating content shows
up as a delta rather than an absolute number let me check the engine ladder again`)

func randProse(rng *rand.Rand, n int) string {
	var sb strings.Builder
	for sb.Len() < n {
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(proseWords[rng.Intn(len(proseWords))])
	}
	return sb.String()
}

// randCommandOutput imitates tool output: paths, hex digests, quoted fragments and the
// occasional long token, which is what the candidate scanner actually meets.
func randCommandOutput(rng *rand.Rand, n int) string {
	var sb strings.Builder
	sb.Grow(n + 128)
	for sb.Len() < n {
		switch rng.Intn(6) {
		case 0:
			fmt.Fprintf(&sb, "internal/scrub/%s.go:%d:%d: %s\n",
				proseWords[rng.Intn(len(proseWords))], rng.Intn(900)+1, rng.Intn(80)+1,
				randProse(rng, 40))
		case 1:
			fmt.Fprintf(&sb, "%s  refs/heads/%s\n", randString(rng, hexDigits, 40),
				proseWords[rng.Intn(len(proseWords))])
		case 2:
			fmt.Fprintf(&sb, "  \"%s\": \"%s\",\n", proseWords[rng.Intn(len(proseWords))],
				randString(rng, tokenAlphabet, 8+rng.Intn(30)))
		case 3:
			fmt.Fprintf(&sb, "ok  \tgithub.com/QuesmaOrg/quesma-shipper/internal/%s\t%d.%03ds\n",
				proseWords[rng.Intn(len(proseWords))], rng.Intn(9), rng.Intn(999))
		default:
			sb.WriteString(randProse(rng, 60+rng.Intn(60)))
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// benchRealDataCap bounds how much of the tree one iteration scrubs: enough to dominate any
// fixed cost, small enough to keep a run coffee-length.
const benchRealDataCap = 256 << 20

// BenchmarkScrubRealData is the measurement that counts: a real transcript tree, whose value
// lengths, secret density and prose no generator reproduces. It skips unless SCRUB_BENCH_DIR
// names a directory of .jsonl files, so CI never depends on private data.
//
//	SCRUB_BENCH_DIR=$HOME/.claude/projects go test ./internal/transforms/ \
//	    -bench BenchmarkScrubRealData -benchmem -run '^$' -benchtime 1x
//
// Run it serially: it is minutes long, and a benchmark sharing the machine moves the number
// more than most changes do.
func BenchmarkScrubRealData(b *testing.B) {
	root := os.Getenv("SCRUB_BENCH_DIR")
	if root == "" {
		b.Skip("set SCRUB_BENCH_DIR to a directory of .jsonl transcripts (e.g. ~/.claude/projects)")
	}

	type file struct {
		name    string
		payload []byte
	}
	var files []file
	total := 0
	// Deterministic order, so two runs over the same tree scrub the same sample.
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if total >= benchRealDataCap {
			return fs.SkipAll
		}
		if d.IsDir() || filepath.Ext(path) != ".jsonl" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, file{name: path, payload: raw})
		total += len(raw)
		return nil
	})
	require.NoErrorf(b, err, "load %s: %v", root, err)
	require.NotEqualf(b, 0, total, "no .jsonl files under %s", root)
	b.Logf("real corpus: %d files, %.1f MiB", len(files), float64(total)/(1<<20))

	cfg := DefaultConfig()
	cfg.Username = "devuser"
	s, err := New(cfg)
	require.NoError(b, err)
	hint := Hint{Family: "claude-code", JSONL: true}
	b.SetBytes(int64(total))
	b.ReportAllocs()
	for b.Loop() {
		for _, f := range files {
			if _, err := s.Scrub(f.payload, hint); err != nil {
				b.Fatalf("scrub %s: %v", f.name, err)
			}
		}
	}
}
