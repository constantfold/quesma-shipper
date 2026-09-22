package sqliteread

import (
	"database/sql"
	"fmt"
	"strings"
)

// query runs the declared read and applies the compiled filter.
func query(db *sql.DB, o Options) (Result, error) {
	var res Result

	// Prefix parameters are bound, never interpolated, so a prefix from anywhere else cannot rewrite the query.
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "SELECT key, value FROM %s", quoteIdent(o.Table))
	var args []any
	if len(o.KeyPrefixes) > 0 {
		sb.WriteString(" WHERE ")
		for i, p := range o.KeyPrefixes {
			if i > 0 {
				sb.WriteString(" OR ")
			}
			sb.WriteString("key LIKE ? ESCAPE '\\'")
			args = append(args, likeEscaper.Replace(p)+"%")
		}
	}
	// Ordered, so a read is reproducible and an enricher's output does not depend on SQLite's row order.
	sb.WriteString(" ORDER BY key")

	rows, err := db.Query(sb.String(), args...)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()

	for rows.Next() {
		if len(res.Rows) >= o.MaxRows {
			return res, ErrTruncated
		}
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return Result{}, err
		}

		// The compiled filter, applied to every row of every read: auth material lives in the same database as the trajectories.
		if keyDenied(key) {
			res.DeniedKeys++
			continue
		}
		cleaned, stripped := scrubValue(value)
		res.StrippedFields += stripped
		if cleaned == nil {
			// Dropping the row is the only outcome that cannot leak the field.
			res.DeniedKeys++
			continue
		}
		res.Rows = append(res.Rows, Row{Key: key, Value: cleaned})
	}
	if err := rows.Err(); err != nil {
		return Result{}, err
	}
	return res, nil
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// Prefixes remain literal when bound as LIKE parameters.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
