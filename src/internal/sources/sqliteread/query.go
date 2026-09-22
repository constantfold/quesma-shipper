package sqliteread

import (
	"database/sql"
	"strings"
)

func query(db *sql.DB, o Options) (Result, error) {
	// Prefixes are bound, never interpolated, and stay literal under LIKE.
	conds := make([]string, len(o.KeyPrefixes))
	args := make([]any, len(o.KeyPrefixes))
	for i, p := range o.KeyPrefixes {
		conds[i] = `key LIKE ? ESCAPE '\'`
		args[i] = likeEscaper.Replace(p) + "%"
	}
	q := `SELECT key, value FROM "` + strings.ReplaceAll(o.Table, `"`, `""`) + `"`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " OR ")
	}
	// Ordered, so an enricher's output does not depend on SQLite's row order.
	rows, err := db.Query(q+" ORDER BY key", args...)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()

	var res Result
	for rows.Next() {
		if len(res.Rows) >= maxRows {
			res.Truncated = true
			return res, nil
		}
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return Result{}, err
		}
		// Applied to every row of every read: auth material lives in the same database as the trajectories.
		if !keyDenied(key) {
			res.Rows = append(res.Rows, Row{Key: key, Value: scrubValue(value)})
		}
	}
	if err := rows.Err(); err != nil {
		return Result{}, err
	}
	return res, nil
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
