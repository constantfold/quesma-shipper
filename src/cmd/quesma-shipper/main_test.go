package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
)

// The verb is what a reader needs to tell a crash in `enroll` from one in the daemon.
func TestVerbOfNamesTheFirstNonFlagArgument(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"quesma-shipper", "sync"}, "sync"},
		{[]string{"quesma-shipper", "-q", "sync"}, "sync"},
		{[]string{"quesma-shipper", "state", "prune"}, "state"},
		{[]string{"quesma-shipper", "--version"}, "quesma-shipper"},
		{[]string{"quesma-shipper"}, "quesma-shipper"},
	} {
		assert.Equal(t, verbOf(tc.args), tc.want)
	}
}

// A crash prints its stack to stderr and persists only the fact, for the next heartbeat.
func TestReportPanicPrintsTheStackAndPersistsTheFact(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	var errOut bytes.Buffer
	reportPanic(&errOut, []string{"quesma-shipper", "enroll", "--invite", "x"}, "boom")

	assert.Containsf(t, errOut.String(), "panic: boom", "the panic did not reach stderr:\n%s", errOut.String())
	assert.Truef(t, strings.Contains(errOut.String(), "runtime/debug.Stack") || strings.Contains(errOut.String(), "goroutine"), "the stack did not reach stderr:\n%s", errOut.String())

	dir, err := app.StateDirWithoutConfig()
	if err != nil {
		t.Skipf("no resolvable state directory here: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "last-failure.json"))
	require.NoErrorf(t, err, "the crash was not persisted under %s: %v", dir, err)
	// The verb, so a crash in enroll is distinguishable from one in the daemon.
	assert.Truef(t, strings.Contains(string(raw), "enroll") && strings.Contains(string(raw), "boom"), "the record does not say what crashed:\n%s", raw)
	// The stack must NOT be there: it is the one diagnostic that can carry payload text.
	assert.NotContainsf(t, string(raw), "goroutine", "a stack reached the persisted record:\n%s", raw)
}
