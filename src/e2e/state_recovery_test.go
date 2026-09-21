// The fingerprint document is a cache of what the archive holds, not the authority on it: a
// document that cannot be loaded is replaced, and the plane answers for every object the empty
// store does not know, so the loss costs a re-hash and a HEAD per object, not a re-upload.
package e2e

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

const grownLine = `{"type":"user","uuid":"u3","message":{"role":"user","content":[{"type":"text","text":"one more"}]}}`

func TestALostDocumentReShipsOnlyWhatChanged(t *testing.T) {
	w := stageWorld(t)
	username := realUsername(t)
	stageClaudeSession(t, w, username, claudeSessionID)
	grown := stageClaudeSession(t, w, username, numericSessionID)
	writeConfig(t, w, "sources:\n  - id: project-map\n    enabled: false\n  - id: claude-account\n    enabled: false\n")

	runOneShot(t)
	require.Equal(t, 2, len(mirrorObjects(collect(t, w))))

	appendLine(t, grown, grownLine)
	require.NoError(t, os.WriteFile(filepath.Join(statePath(w), engine.FileName), []byte("this is not a document\n"), 0o600))
	runOneShot(t)
	w.plane.assertClean(t)

	// Both commit: the plane answered for the unchanged one and the grown one was PUT, so
	// the unchanged key keeps its single version.
	assert.Equal(t, 2, countOf(shippedFromLog(t, w), claudeSource))
	present := w.plane.answeredPresent()
	for _, o := range mirrorObjects(collect(t, w)) {
		changed := strings.Contains(string(o.Payload), "one more")
		want := 1
		if changed {
			want = 2
		}
		assert.Equal(t, w.store.versions(o.Key), want)
		assert.NotEqual(t, slices.Contains(present, o.Key), changed)
	}

	// The replacement document loads, and the next run trusts it: nothing to send.
	if _, err := engine.Peek(statePath(w)); err != nil {
		t.Fatalf("the replacement document does not load: %v", err)
	}
	out := runOneShot(t)
	assert.Equal(t, 0, countOf(shippedFromLog(t, w), claudeSource))
	assert.NotEqual(t, 0, summary(t, out)["unchanged"])
}
