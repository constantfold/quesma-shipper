package controlplane

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// CacheFile holds the last remote config this install fetched, so a run with no reachable backend still has a remote layer.
const CacheFile = "remote-config.json"

// cacheSchema versions the file. An older cache is treated as "no cache" until the next successful fetch rewrites it.
const cacheSchema = 3

// Cached is the last remote config fetched; Config is the served document verbatim, reparsed on load.
type Cached struct {
	CacheSchema int       `json:"cache_schema"`
	Config      []byte    `json:"config"`
	FetchedAt   time.Time `json:"fetched_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// SaveCache persists a fetched config.
func SaveCache(stateDir string, c Cached) error {
	c.CacheSchema = cacheSchema
	return platform.WriteJSON(filepath.Join(stateDir, CacheFile), c, 0o600)
}

// LoadCache reads the cached config. A missing file is an error the caller treats as "no remote layer".
func LoadCache(stateDir string) (*Cached, error) {
	raw, _, err := platform.ReadWhole(filepath.Join(stateDir, CacheFile), maxResponseBytes)
	if err != nil {
		return nil, err
	}
	var c Cached
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("backend: parse cached config: %w", err)
	}
	if c.CacheSchema != cacheSchema {
		return nil, fmt.Errorf("backend: cache_schema %d, this client speaks %d", c.CacheSchema, cacheSchema)
	}
	return &c, nil
}

// Expired reports whether the config is past its expiry. Expiry does NOT stop collection: the
// scope kept was already served and can never widen, while halting would lose data for good.
func (c Cached) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt)
}
