package transforms_test

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// BenchmarkScrubSyntheticAt is BenchmarkScrubSynthetic's corpus with '@' in it: the original has
// none, so the email rule (the most expensive pattern on real data) never fires there. A second
// benchmark rather than an edit to the first, whose numbers are the tracked series.
func BenchmarkScrubSyntheticAt(b *testing.B) {
	benchmarkSynthetic(b, syntheticTranscriptAt, syntheticBigValueAt)
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

func syntheticBigValueAt(size int) []byte {
	return syntheticBigValueWith(size, 20260819, randCommandOutputAt)
}
