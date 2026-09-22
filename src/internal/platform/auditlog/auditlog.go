// Package auditlog is the append-only local log behind `quesma-shipper log`, written for the person
// whose data it is: the file, bytes, density, rule hit counts, object key, decision and config
// version in force, never a redacted value or file contents. Rejected configs land here too.
package auditlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

const FileName = "audit.log"

// Decision is aliased from the contract layer: one spelling for the engine, the CLI and this log.
type Decision = formats.Decision

const (
	DecisionShipped   = formats.DecisionShipped
	DecisionUnchanged = formats.DecisionUnchanged
	DecisionSkipped   = formats.DecisionSkipped
	DecisionParked    = formats.DecisionParked
	DecisionFailed    = formats.DecisionFailed
)

type Entry struct {
	At       time.Time `json:"at"`
	RunID    string    `json:"run_id,omitempty"`
	Decision Decision  `json:"decision"`
	SourceID string    `json:"source_id,omitempty"`

	// File is the native path with the username placeholder applied.
	File string `json:"file,omitempty"`

	BytesIn  int64 `json:"bytes_in,omitempty"`
	BytesOut int64 `json:"bytes_out,omitempty"`

	RedactionDensity float64        `json:"redaction_density,omitempty"`
	RuleHits         map[string]int `json:"rule_hits,omitempty"`

	ObjectKey     string `json:"object_key,omitempty"`
	ConfigVersion int    `json:"config_version,omitempty"`

	// Reason explains a skip, park, failure or rejection, or a shipped entry the archive already held.
	Reason string `json:"reason,omitempty"`
}

type Log struct {
	mu    sync.Mutex
	path  string
	runID string
}

// SetRunID correlates later entries with the crash journal and the heartbeat.
func (l *Log) SetRunID(id string) { l.runID = id }

// Open prepares the log. The directory is created if needed.
func Open(stateDir string) (*Log, error) {
	if err := platform.EnsureDir(stateDir, 0o700); err != nil {
		return nil, err
	}
	return &Log{path: filepath.Join(stateDir, FileName)}, nil
}

// Path is where the log lives, for `status` and `doctor`.
func (l *Log) Path() string { return l.path }

// Append records one decision. A nil log disables auditing, as in preview mode.
func (l *Log) Append(e Entry) error {
	if l == nil {
		return nil
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.RunID == "" {
		e.RunID = l.runID
	}
	e = sanitize(e)

	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("auditlog: encode: %w", err)
	}
	body = append(body, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	// Checked under the same lock that serialises appends, so a rotation cannot land mid-write.
	platform.RotateLog(l.path)

	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("auditlog: open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return fmt.Errorf("auditlog: write: %w", err)
	}
	return nil
}

// sanitize enforces the never-record list structurally: Reason is the only free text, so it is flattened and truncated.
func sanitize(e Entry) Entry {
	const maxReason = 500
	e.Reason = strings.NewReplacer("\n", " ", "\r", " ").Replace(e.Reason)
	if len(e.Reason) > maxReason {
		e.Reason = e.Reason[:maxReason] + "…(truncated)"
	}
	if strings.Contains(e.Reason, "__REDACTED:") {
		// A sentinel in a reason means the message quoted payload, so the message does not belong here.
		e.Reason = "(reason withheld: contained payload-derived text)"
	}
	return e
}

// Tail returns the last n entries, newest last, reading from the end (see rotate.go).
func Tail(path string, n int) ([]Entry, error) {
	raw, err := readTail(path, n)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("auditlog: read: %w", err)
	}

	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	out := make([]Entry, 0, len(lines))
	for _, line := range lines {
		// A malformed line is skipped: a torn last line from a crash must not make the whole log unreadable.
		var e Entry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}
