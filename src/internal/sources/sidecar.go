package sources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// ProjectRecord is one directory-to-repository mapping. An empty Remote or Project is a legal
// outcome, since not every session is tied to a repository; GaveUp then explains the gap.
type ProjectRecord struct {
	At   string `json:"at"`
	Kind string `json:"kind"`
	// ProjectDir is the agent's OWN encoded project directory name, the only join key present in trajectory paths.
	ProjectDir string `json:"project_dir"`
	// CWD is placeholdered; Remote is normalised to host/path.
	CWD      string `json:"cwd,omitempty"`
	Remote   string `json:"remote,omitempty"`
	Project  string `json:"project,omitempty"`
	SourceID string `json:"source_id,omitempty"`
	GaveUp   string `json:"gave_up,omitempty"`
}

// discoverSidecar records repository mappings before the sessions that reveal them are reaped.
func discoverSidecar(req Request) (Discovery, error) {
	src := req.Source
	d := Discovery{Health: AgentAbsent, Sniff: SniffOK}

	probe := src.CWDProbe
	if probe == nil {
		d.Reason = "sidecar source has no cwd_probe"
		return d, nil
	}
	now := time.Now().UTC()
	if req.Now != nil {
		now = req.Now()
	}

	// Inputs are the candidate files of the sources this probe names, one record per project
	// directory: the mapping is a property of the directory, not of a file.
	anyInput := false
	seen := map[string]bool{}
	var records []ProjectRecord
	for _, other := range req.All {
		if !slices.Contains(probe.From, other.ID) || other.Root == "" || !other.Enabled {
			continue
		}
		// The map exists to name repositories; not the ones nobody wants named.
		candidates, _, _, _ := walkGlobs(other, req.Deny, req.Ignore)
		anyInput = anyInput || len(candidates) > 0
		for _, c := range candidates {
			projectDir := projectDirOf(c.RelPath)
			if projectDir == "" || seen[projectDir] {
				continue
			}
			seen[projectDir] = true
			rec := ProjectRecord{
				At:   now.Format(time.RFC3339),
				Kind: "git_project_map",
				// Placeholdered at build time: this directory NAME encodes the username, and the file sits on disk between runs.
				ProjectDir: formats.ApplyUserPlaceholder(projectDir, req.Username),
				SourceID:   other.ID,
			}
			if cwd, ok := probeCWD(c.Path, probe); ok {
				rec.CWD = formats.ApplyUserPlaceholder(cwd, req.Username)
				rec.Remote, rec.Project, rec.GaveUp = gitRemoteFor(cwd, src.GitRead)
			} else {
				rec.GaveUp = "no cwd field found in the head of the file"
			}
			records = append(records, rec)
		}
	}
	if !anyInput {
		d.Reason = "no probe input sources resolved"
		return d, nil
	}

	slices.SortFunc(records, func(a, b ProjectRecord) int { return strings.Compare(a.ProjectDir, b.ProjectDir) })
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return d, fmt.Errorf("gather: encode project record: %w", err)
		}
	}

	// Replaced, not appended: the inventory describes what exists NOW, and appending would grow an unbounded log.
	dir := filepath.Join(req.StateDir, "inventories")
	if err := platform.EnsureDir(dir, 0o700); err != nil {
		return d, err
	}
	name := src.ID + ".inventory.jsonl"
	path := filepath.Join(dir, name)
	if err := platform.WriteAtomic(path, body.Bytes(), 0o600); err != nil {
		return d, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return d, err
	}

	d.Health = Collected
	d.Candidates = []Candidate{{Path: path, RelPath: name, Size: info.Size(), MTime: info.ModTime().UTC(),
		Load: fileLoader(path, src.MaxFileBytes)}}
	d.Reason = fmt.Sprintf("%d project directories mapped", len(records))
	return d, nil
}

// projectDirOf takes the agent's encoded project directory out of a relative path. Only a real
// projects/<encoded-cwd> segment counts: a bogus join key is worse than no record at all.
func projectDirOf(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i, seg := range parts {
		if seg == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// probeCWD reads the first cwd-shaped value out of the head of a file, bounded on purpose: the client does not parse.
func probeCWD(path string, probe *CWDProbe) (string, bool) {
	head, _, err := readHead(path, probe.ScanBytes)
	if err != nil {
		return "", false
	}
	for line := range strings.SplitSeq(string(head), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		for _, field := range probe.Fields {
			if v := lookupField(rec, field); v != "" {
				return v, true
			}
		}
	}
	return "", false
}

// lookupField resolves a dotted field name, so a config can name payload.cwd as easily as cwd.
func lookupField(rec map[string]json.RawMessage, field string) string {
	key, rest, nested := strings.Cut(field, ".")
	raw := rec[key]
	if len(raw) == 0 {
		return ""
	}
	if nested {
		var next map[string]json.RawMessage
		if json.Unmarshal(raw, &next) != nil {
			return ""
		}
		return lookupField(next, rest)
	}
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}
