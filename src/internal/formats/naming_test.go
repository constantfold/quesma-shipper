package formats_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

const install = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

func keyA() []byte {
	k := make([]byte, formats.NameKeySize)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// Keyed, fixed length however long the path, and stable, so a re-ship after state loss is an overwrite.
func TestMirrorName(t *testing.T) {
	const p = "projects/proj/a.jsonl"
	assert.NotEqual(t, formats.MirrorName(bytes.Repeat([]byte{0xff}, formats.NameKeySize), p), formats.MirrorName(keyA(), p))
	long := formats.CanonicalPath(strings.Repeat("verylongsegmentname/", 500)+"leaf.jsonl", "jane")
	assert.Len(t, formats.MirrorName(keyA(), "a"), 64)
	assert.Len(t, formats.MirrorName(keyA(), long), 64)
	assert.Equal(t, formats.MirrorName(keyA(), p), formats.MirrorName(keyA(), p))
}

// Home paths differing only by user name converge; over-replacing is the worse failure, since it merges two files onto one key.
func TestUserPlaceholder(t *testing.T) {
	assert.Equal(t, formats.CanonicalPath("projects/-Users-bob-work-api/s.jsonl", "bob"),
		formats.CanonicalPath("projects/-Users-jane-work-api/s.jsonl", "jane"))
	for _, c := range []struct{ in, username, want string }{
		{"notes/janes-notes.md", "jane", "notes/janes-notes.md"},
		{"notes/mariajane.txt", "jane", "notes/mariajane.txt"},
		{"jane/x.txt", "jane", "__USER__/x.txt"},
		{"-Users-jane-work", "jane", "-Users-__USER__-work"},
		{"a/b.txt", "a", "a/b.txt"},
		{"projects/x.jsonl", "", "projects/x.jsonl"},
	} {
		assert.Equal(t, c.want, formats.ApplyUserPlaceholder(c.in, c.username))
	}
}

// The encoding has to be injective, or two files collide and one overwrites the other.
func TestSegmentEncodingIsInjective(t *testing.T) {
	seen := map[string]string{}
	for _, in := range []string{"a b", "a%20b", "a%2520b", "a/b", "a-b", "a_b", "a.b", "a~b", "100%", "100%25", "été", "%C3%A9"} {
		got := formats.CanonicalPath(in, "jane")
		assert.NotContainsf(t, seen, got, "collision: %q and %q both encode to %q", seen[got], in, got)
		seen[got] = in
	}
}

// Keys are identity-first at one depth, state included, so erasure is one sweep; the leaf reveals nothing of the path.
func TestKeyLayout(t *testing.T) {
	got, err := formats.MirrorKey("default", install, "claude-code-transcripts", keyA(), "projects/proj/a.jsonl")
	require.NoError(t, err)
	assert.Equal(t, "v1/organization=default/install="+install+"/mirror/source=claude-code-transcripts/"+
		"28547a64a206a3b4d14d27ccbf75019e758fc176524ac0ea7b0a83ef7df78ef4.age", got)

	enterprise, err := formats.MirrorKey("acme", install, "claude-code-transcripts", keyA(), "projects/proj/a.jsonl")
	require.NoError(t, err)
	assert.Equal(t, strings.Count(got, "/"), strings.Count(enterprise, "/"))

	state, err := formats.StateKey("default", install, "heartbeat.json.age")
	require.NoError(t, err)
	assert.Equal(t, "v1/organization=default/install="+install+"/state/heartbeat.json.age", state)

	key, err := formats.MirrorKey("default", install, "claude-code-transcripts", keyA(),
		formats.CanonicalPath("projects/-Users-jane-work-secret-project/session.jsonl", "jane"))
	require.NoError(t, err)
	leaf := key[strings.LastIndex(key, "/")+1:]
	for _, fragment := range []string{"jane", "secret-project", "session", "projects", "Users", ".jsonl"} {
		assert.NotContains(t, leaf, fragment)
	}
	assert.Len(t, leaf, 64+len(".age"))
}

// A source or org id carrying "/" or "=" could forge a path into another install's subtree.
func TestKeySegmentsAreValidated(t *testing.T) {
	for _, c := range []struct{ org, id, source string }{
		{"../../etc", install, "s"},
		{"default", install, "../other"},
		{"default", install, "a/b"},
		{"default", install, "install=other"},
		{"default", "", "s"},
		{"", install, "s"},
		{"default", install, "Capitals"},
	} {
		_, err := formats.MirrorKey(c.org, c.id, c.source, keyA(), "a.jsonl")
		assert.Error(t, err, c)
	}
	_, err := formats.MirrorKey("default", install, "s", []byte("too short"), "a.jsonl")
	assert.Error(t, err, "a name_key of the wrong size must be refused")
	_, err = formats.StateKey("default", install, "nested/name")
	assert.Error(t, err, "a state object name containing a slash must be refused")
}
