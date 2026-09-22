package engine

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// The fingerprint store: one JSON document, replaced atomically, beside a separate lock file so the
// document itself is never held open. Losing it costs a re-hash, never a re-upload.

const (
	// StateSchema versions the document. A mismatch means downgrade or corruption: reject, never guess.
	StateSchema = 1
	FileName    = "fingerprints.json"
	lockName    = "fingerprints.lock"

	// Roughly a hundred thousand entries at 400 bytes each; Prune and Reset may read further.
	maxDocumentBytes      = 64 << 20
	pruneMaxDocumentBytes = 512 << 20
)

// ErrLocked means another flush holds the store; the caller should try later rather than wait.
var ErrLocked = errors.New("state: store is locked by another flush")

// Key identifies one fingerprint.
type Key struct {
	SourceID   string
	NativePath string
}

// Fingerprint is what the store remembers about one file.
type Fingerprint struct {
	// Size and mtime are the cheap pre-filter; the content hash is the authority. SourceHash also
	// marks a completed ship: only the post-verified-PUT commit may write it, never a failure path.
	SourceSize  int64
	SourceMTime time.Time
	SourceHash  string

	// Derived entries only.
	Enricher   *EnricherRef
	OutputHash string

	// A parked entry waits for backoff; Attempts counts consecutive failures. There is no max-retry.
	Parked       bool
	LastError    string
	BackoffUntil time.Time
	Attempts     int
}

// EnricherRef identifies the enricher that produced a derived entry, in the manifest's own shape.
type EnricherRef = transforms.EnricherRef

// Document is the whole on-disk state, as read by Peek.
type Document struct {
	InstallID   string
	UpdatedAt   time.Time
	SourceSpecs map[string]string
	Entries     map[Key]Fingerprint
}

// ForeignTo reports whether another install wrote this document. An empty id on either side is never foreign.
func (d Document) ForeignTo(installID string) bool {
	return d.InstallID != "" && installID != "" && d.InstallID != installID
}

// Store is an open, locked fingerprint store.
type Store struct {
	dir       string
	installID string
	lock      *os.File
	specs     map[string]string
	entries   map[Key]Fingerprint
	corrupt   bool
}

// Corrupt says the document could not be loaded and was discarded, so the run can report it.
func (s *Store) Corrupt() bool { return s.corrupt }

// Open takes the flock, non-blocking, and loads the document: a busy store is refused, not queued.
func Open(stateDir, installID string) (*Store, error) {
	return open(stateDir, installID, maxDocumentBytes)
}

func open(stateDir, installID string, maxBytes int64) (*Store, error) {
	if err := platform.EnsureDir(stateDir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(stateDir, lockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("state: open lock: %w", err)
	}
	if err := platform.LockFile(lock); err != nil {
		lock.Close()
		return nil, ErrLocked
	}
	s := &Store{dir: stateDir, installID: installID, lock: lock}

	// An unloadable document is discarded, never fatal: the archive answers for what it holds.
	doc, err := load(stateDir, maxBytes)
	if err == nil && doc.ForeignTo(installID) {
		err = fmt.Errorf("state: %s belongs to install %s, this install is %s",
			filepath.Join(stateDir, FileName), doc.InstallID, installID)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s could not be loaded (%v); continuing from an empty store\n", FileName, err)
		doc = Document{SourceSpecs: map[string]string{}, Entries: map[Key]Fingerprint{}}
		s.corrupt = true
	}
	s.specs, s.entries = doc.SourceSpecs, doc.Entries
	return s, nil
}

// Close releases the lock.
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	platform.UnlockFile(s.lock)
	err := s.lock.Close()
	s.lock = nil
	return err
}

// editStore is the shell both operator overrides share. A discarded document is always written
// back: the override is the operator's chance to replace it.
func editStore(stateDir, installID string, dryRun bool, edit func(*Store) int) (int, error) {
	s, err := open(stateDir, installID, pruneMaxDocumentBytes)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	changed := edit(s)
	if dryRun || (changed == 0 && !s.corrupt) {
		return changed, nil
	}
	return changed, s.flush()
}

// Prune removes entries whose file is gone. A file on an unmounted volume reads as gone, which is
// why it stays a command.
func Prune(stateDir, installID string, dryRun bool) (removed, kept int, err error) {
	removed, err = editStore(stateDir, installID, dryRun, func(s *Store) int {
		before := len(s.entries)
		maps.DeleteFunc(s.entries, func(k Key, _ Fingerprint) bool {
			_, err := os.Lstat(k.NativePath)
			return err != nil
		})
		kept = len(s.entries)
		return before - kept
	})
	return removed, kept, err
}

// Reset forgets every fingerprint; unchanged bytes come back already_present, so it never forces a
// re-seal. The document is replaced rather than deleted, so the install id survives.
func Reset(stateDir, installID string, dryRun bool) (removed int, err error) {
	return editStore(stateDir, installID, dryRun, func(s *Store) int {
		removed := len(s.entries)
		s.entries = map[Key]Fingerprint{}
		return removed
	})
}

// Peek reads the document without the lock, so status and doctor never contend with a flush.
func Peek(stateDir string) (Document, error) {
	return load(stateDir, maxDocumentBytes)
}

func (s *Store) Get(k Key) (Fingerprint, bool) {
	fp, ok := s.entries[k]
	return fp, ok
}

func (s *Store) Len() int { return len(s.entries) }

// CommitAll records several fingerprints in one document replacement.
// A crash before the replace re-runs those files onto their existing keys. Never make this a database.
func (s *Store) CommitAll(updates map[Key]Fingerprint) error {
	maps.Copy(s.entries, updates)
	return s.flush()
}

// EnsureSpec records which spec generation a source's entries belong to, dropping them all when it
// differs. Per source, never the global config_version, which would invalidate the whole fleet.
func (s *Store) EnsureSpec(sourceID, specFP string) (dropped int, err error) {
	stored, known := s.specs[sourceID]
	if known && stored == specFP {
		return 0, nil
	}
	if known {
		before := len(s.entries)
		maps.DeleteFunc(s.entries, func(k Key, _ Fingerprint) bool { return k.SourceID == sourceID })
		dropped = before - len(s.entries)
	}
	if s.specs == nil {
		s.specs = map[string]string{}
	}
	s.specs[sourceID] = specFP
	return dropped, s.flush()
}

// DropVanished forgets this source's entries whose file discovery no longer sees.
func (s *Store) DropVanished(sourceID string, live map[string]bool) (int, error) {
	before := len(s.entries)
	maps.DeleteFunc(s.entries, func(k Key, _ Fingerprint) bool { return k.SourceID == sourceID && !live[k.NativePath] })
	dropped := before - len(s.entries)
	if dropped == 0 {
		return 0, nil
	}
	return dropped, s.flush()
}

func (s *Store) flush() error {
	body, err := encode(s.installID, time.Now().UTC().Truncate(time.Second), s.specs, s.entries)
	if err != nil {
		return err
	}
	return platform.WriteAtomic(filepath.Join(s.dir, FileName), body, 0o600)
}
