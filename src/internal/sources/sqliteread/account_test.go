package sqliteread_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources/sqliteread"
)

func TestCursorCredentialReadIsSeparateFromCollectedRows(t *testing.T) {
	path := newStore(t, map[string]string{
		"cursorAuth/accessToken":         "fixture-access",
		"cursorAuth/refreshToken":        "fixture-refresh",
		"cursorAuth/cachedEmail":         "dev@example.org",
		"cursorAuth/cachedTeam":          `{"name":"team","future":9007199254740993}`,
		"cursorAuth/cachedScopedProfile": `{"future":null}`,
		"cursorAuth/futureSecret":        "not-collected",
	})
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	values, token, err := sqliteread.CursorAccount(context.Background(), path)
	require.NoError(t, err)
	require.Truef(t, token == "fixture-access" && len(values) == 3, "unexpected metadata count %d", len(values))
	raw, err := json.Marshal(values)
	require.NoError(t, err)
	for _, s := range []string{"fixture-access", "fixture-refresh", "not-collected"} {
		require.NotContains(t, string(raw), s, "credential entered metadata")
	}
	require.Contains(t, string(raw), `"future":9007199254740993`, "provider field lost")
	generic, err := sqliteread.Read(sqliteread.Options{Path: path, ScratchDir: t.TempDir(), Table: "ItemTable", KeyPrefixes: []string{"cursorAuth/"}})
	require.NoError(t, err)
	for _, row := range generic.Rows {
		require.True(t, row.Key != "cursorAuth/accessToken" && row.Key != "cursorAuth/refreshToken", "generic collection acquired credentials")
	}
	after, err := os.ReadFile(path)
	require.True(t, err == nil && bytes.Equal(before, after), "account read changed store", err)
	missing := filepath.Join(t.TempDir(), "absent.vscdb")
	if _, _, err := sqliteread.CursorAccount(context.Background(), missing); err == nil {
		t.Fatal("missing store succeeded")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("read created database")
	}
}
