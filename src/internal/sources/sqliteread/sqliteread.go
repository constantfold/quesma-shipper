// Package sqliteread reads live agent SQLite databases as ENRICHER INPUT ONLY; no rows ever ship. Three read methods,
// tried in order and recorded in the manifest: read-only in-place open, VACUUM INTO scratch snapshot, cold raw
// copy of db plus -wal/-shm. It never opens the original read-write and never byte-copies a live database.
package sqliteread

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ReadMethod names how a read was obtained; the values are what manifest.schema.json enumerates.
type ReadMethod string

const (
	ReadInPlace  ReadMethod = "readonly_open"    // the live file, opened read-only
	ReadSnapshot ReadMethod = "scratch_snapshot" // a consistent VACUUM INTO copy, queried and deleted
	ReadColdCopy ReadMethod = "cold_copy"        // a raw copy of a database nothing is writing, sidecars included
)

const (
	coldAfter = 5 * time.Minute // generous: being wrong means copying a live database
	maxRows   = 200_000
)

// Row is one key/value pair, already filtered.
type Row struct {
	Key   string
	Value []byte
}

type Result struct {
	Rows   []Row
	Method ReadMethod

	// A flag, not an error: an error would send the read to the next fallback.
	Truncated bool
}

type Options struct {
	Path string // never opened read-write

	// Where snapshot and cold-copy reads put their copies: under the state directory, never beside the source.
	ScratchDir string

	// The read's declared scope, named by the enricher, not discovered here.
	Table       string
	KeyPrefixes []string

	// StartAt skips the methods before it, so tests can exercise a fallback. Empty starts at the top.
	StartAt ReadMethod
}

// errSkipped reports a method StartAt skipped, so a failure message cannot imply it was tried.
var errSkipped = errors.New("skipped by StartAt")

// Read tries each method in order, falling back only when a method cannot read the database.
func Read(o Options) (Result, error) {
	if o.Path == "" {
		return Result{}, errors.New("sqliteread: no database path")
	}
	if o.Table == "" {
		return Result{}, errors.New("sqliteread: no table declared: an enricher's scope is declared, not discovered")
	}

	inPlaceErr, snapshotErr := errSkipped, errSkipped
	if o.StartAt == "" || o.StartAt == ReadInPlace {
		res, err := readAt(o, o.Path, ReadInPlace)
		if err == nil {
			return res, nil
		}
		inPlaceErr = err
	}
	// A snapshot is consistent where a byte copy is not, so it beats a raw copy even on a cold database.
	if o.StartAt != ReadColdCopy {
		res, err := readSnapshot(o)
		if err == nil {
			return res, nil
		}
		snapshotErr = err
	}
	res, err := readColdCopy(o)
	if err == nil {
		return res, nil
	}
	return Result{}, fmt.Errorf("sqliteread: every read method failed for %s:\n  in-place: %v\n  snapshot: %v\n  cold copy: %v",
		o.Path, inPlaceErr, snapshotErr, err)
}

// Never use immutable=1: it skips the WAL and can silently return stale data.
func readAt(o Options, path string, method ReadMethod) (Result, error) {
	dsn := "file:" + path + "?mode=ro&_pragma=query_only(1)"
	if method == ReadInPlace {
		// Briefly wait for live writers before paying for a snapshot.
		dsn += "&_pragma=busy_timeout(2000)&_txlock=deferred"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return Result{}, err
	}
	defer db.Close()
	res, err := query(db, o)
	res.Method = method
	return res, err
}

func readSnapshot(o Options) (result Result, err error) {
	if o.ScratchDir == "" {
		return Result{}, errors.New("sqliteread: no scratch directory for a snapshot read")
	}
	if err := os.MkdirAll(o.ScratchDir, 0o700); err != nil {
		return Result{}, err
	}

	scratch := filepath.Join(o.ScratchDir, "snapshot-"+sanitise(filepath.Base(o.Path))+".sqlite")
	// A leftover from a crashed run is a corrupt partial that would query as if valid.
	if err := removeSnapshot(scratch); err != nil {
		return Result{}, err
	}
	defer func() {
		if rmErr := removeSnapshot(scratch); rmErr != nil && err == nil {
			// A leftover is a copy of an agent's database in the state directory; worth failing the read over.
			err = fmt.Errorf("sqliteread: snapshot read succeeded but %s could not be removed: %w", scratch, rmErr)
			result = Result{}
		}
	}()

	src, err := sql.Open("sqlite", "file:"+o.Path+"?mode=ro")
	if err != nil {
		return Result{}, err
	}
	defer src.Close()

	// Quoted as a SQL string literal: VACUUM INTO takes an expression, and a path may contain a quote.
	if _, err := src.Exec("VACUUM INTO '" + strings.ReplaceAll(scratch, "'", "''") + "'"); err != nil {
		return Result{}, fmt.Errorf("vacuum into %s: %w", scratch, err)
	}

	return readAt(o, scratch, ReadSnapshot)
}

func readColdCopy(o Options) (result Result, err error) {
	if o.ScratchDir == "" {
		return Result{}, errors.New("sqliteread: no scratch directory for a cold copy")
	}
	info, err := os.Stat(o.Path)
	if err != nil {
		return Result{}, err
	}
	if age := time.Since(info.ModTime()); age < coldAfter {
		return Result{}, fmt.Errorf("database was modified %s ago, which is not cold enough for a raw copy "+
			"(a raw copy of a live database is not consistent)", age.Round(time.Second))
	}

	dir := filepath.Join(o.ScratchDir, "cold-"+sanitise(filepath.Base(o.Path)))
	if err := os.RemoveAll(dir); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, err
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil && err == nil {
			err = fmt.Errorf("sqliteread: cold copy succeeded but %s could not be removed: %w", dir, rmErr)
			result = Result{}
		}
	}()

	copied, err := CopyCold(o.Path, dir)
	if err != nil {
		return Result{}, err
	}

	return readAt(o, copied, ReadColdCopy)
}

// CopyCold copies a database and its sidecars into dir. The sidecars must keep matching basenames, or the copy
// opens without the WAL and silently shows data from before the last checkpoint.
func CopyCold(src, dir string) (string, error) {
	dst := filepath.Join(dir, filepath.Base(src))
	if err := copyFile(src, dst); err != nil {
		return "", err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		// Absent is fine: a checkpointed database has no -wal.
		if _, err := os.Stat(src + suffix); err == nil {
			if err := copyFile(src+suffix, dst+suffix); err != nil {
				return "", err
			}
		}
	}
	return dst, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func sanitise(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			b[i] = '_'
		}
	}
	return string(b)
}

func removeSnapshot(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
