package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// StateSchema versions the document. A mismatch means downgrade or corruption: reject, never guess.
const StateSchema = 1

// The lock is a separate file so the document itself is only ever replaced, never held open.
const (
	FileName = "fingerprints.json"
	lockName = "fingerprints.lock"
)

// maxDocumentBytes bounds the document: roughly a hundred thousand entries at 400 bytes each.
const maxDocumentBytes = 64 << 20

var (
	// ErrLocked means another flush holds the store; the caller should try later rather than wait.
	ErrLocked = errors.New("state: store is locked by another flush")

	// ErrSchemaMismatch means the document was written by a different version.
	ErrSchemaMismatch = errors.New("state: document schema mismatch")
)

// Store is an open, locked fingerprint store.
type Store struct {
	dir       string
	installID string
	lock      *os.File
	specs     map[string]string
	entries   map[Key]Fingerprint

	corrupt bool
}

// Corrupt says the document could not be loaded and was discarded: the run continues from an empty
// store and the first flush replaces the file. Carried out so the discard is reported, not survived.
func (s *Store) Corrupt() bool { return s.corrupt }

// Open takes the flock, non-blocking, and loads the document: a busy store is refused, not queued.
func Open(stateDir, installID string) (*Store, error) {
	return open(stateDir, installID, maxDocumentBytes)
}

// pruneMaxDocumentBytes is what Prune and Reset may read: larger than the ordinary cap, still bounded.
const pruneMaxDocumentBytes = 512 << 20

func open(stateDir, installID string, maxBytes int64) (*Store, error) {
	if err := platform.EnsureDir(stateDir, 0o700); err != nil {
		return nil, err
	}

	lockPath := filepath.Join(stateDir, lockName)
	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("state: open lock: %w", err)
	}
	if err := platform.LockFile(lock); err != nil {
		lock.Close()
		return nil, ErrLocked
	}
	s := &Store{dir: stateDir, installID: installID, lock: lock}

	// Any document that cannot be loaded is discarded, never fatal: the archive answers for what it
	// already holds, so an empty store costs a re-hash, not a re-upload.
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

// editStore is the shell both operator overrides share: it reads past maxDocumentBytes, since a
// past-the-ceiling document must not lock out the override, and writes only what edit changed.
// A discarded document is always written back: the override is the operator's chance to replace it.
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

// Prune removes entries whose file is gone. It tests existence on disk, so a file on an unmounted
// volume reads as gone, which is why it stays a command.
func Prune(stateDir, installID string, dryRun bool) (removed, kept int, err error) {
	removed, err = editStore(stateDir, installID, dryRun, func(s *Store) int {
		gone := 0
		for k := range s.entries {
			if _, statErr := os.Lstat(k.NativePath); statErr == nil {
				kept++
				continue
			}
			gone++
			delete(s.entries, k)
		}
		return gone
	})
	return removed, kept, err
}

// Reset forgets every fingerprint, so the next sync re-hashes the whole history and re-probes the
// archive; unchanged bytes come back already_present, so a reset never forces a re-seal.
// The document is replaced with an empty one rather than deleted, so the install id survives.
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

// Get returns a fingerprint.
func (s *Store) Get(k Key) (Fingerprint, bool) {
	fp, ok := s.entries[k]
	return fp, ok
}

// Len reports how many entries the store holds.
func (s *Store) Len() int { return len(s.entries) }

// CommitAll records several fingerprints in one document replacement. The only durable step in the
// loop, and it happens last: a crash before the replace re-runs those files onto their existing
// keys. Safe under retry-is-re-run. Never make this a database.
func (s *Store) CommitAll(updates map[Key]Fingerprint) error {
	for k, fp := range updates {
		s.entries[k] = fp
	}
	return s.flush()
}

// SpecFor reports the spec generation this source's entries were recorded under.
func (s *Store) SpecFor(sourceID string) (string, bool) {
	stored, known := s.specs[sourceID]
	return stored, known
}

// EnsureSpec records which spec generation this source's entries belong to, dropping them all when
// it differs. Per source and never the global config_version, which would invalidate every
// fingerprint on every machine. Entries with no recorded generation adopt it without dropping.
func (s *Store) EnsureSpec(sourceID, specFP string) (dropped int, err error) {
	stored, known := s.specs[sourceID]
	if known && stored == specFP {
		return 0, nil
	}
	if known {
		for k := range s.entries {
			if k.SourceID == sourceID {
				delete(s.entries, k)
				dropped++
			}
		}
	}
	if s.specs == nil {
		s.specs = map[string]string{}
	}
	s.specs[sourceID] = specFP
	return dropped, s.flush()
}

// DropVanished forgets this source's entries whose file discovery no longer sees, keyed by native
// path. Only a source that collected AND returned candidates proves absence: err on kept-too-long.
func (s *Store) DropVanished(sourceID string, live map[string]bool) (int, error) {
	dropped := 0
	for k := range s.entries {
		if k.SourceID != sourceID {
			continue
		}
		if live[k.NativePath] {
			continue
		}
		delete(s.entries, k)
		dropped++
	}
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
