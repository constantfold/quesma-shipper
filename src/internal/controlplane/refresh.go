package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// Origin says where the remote layer in force came from.
type Origin string

const (
	OriginFetched Origin = "fetched"
	OriginCached  Origin = "cached" // the last config fetched, reused because this run could not get a new one
	OriginNone    Origin = "none"   // no remote layer: an ordinary state, the local layers are a complete configuration
)

// Remote is the org's config, which enters the resolver as an ordinary document layer.
type Remote struct {
	Origin  Origin
	Doc     *config.Document // nil when Origin is OriginNone
	Expired bool             // a config past its expiry is in use; it does not stop collection

	// Err is why a fetch did not happen or was refused: a quiet fallback leaves an operator believing a config change took effect.
	Err error
}

type RefreshOptions struct {
	Enrollment *Enrollment
	StateDir   string
	Now        time.Time
	Offline    bool // `config show` must explain the config in force without a round-trip that changes it
}

// Refresh produces the remote layer for one run: a fetch that parses wins and is cached, and ANY
// failure to obtain a config this client accepts falls back to the last one it did fetch, whose
// expiry does not stop collection. A transcript missed before its source store's reaper runs is gone.
func Refresh(ctx context.Context, o RefreshOptions) Remote {
	if o.Enrollment == nil || o.Enrollment.Endpoint == "" {
		return Remote{Origin: OriginNone}
	}
	fetchErr := errors.New("backend: offline, resolving from the cached config")
	if !o.Offline {
		fetched, err := fetch(ctx, o)
		if err == nil {
			return fetched
		}
		fetchErr = err
	}

	cached, err := LoadCache(o.StateDir)
	var doc *config.Document
	if err == nil {
		doc, err = config.ParseServedDocument(cached.Config)
	}
	if err != nil {
		// Both halves: a cache that no longer parses is a file to delete, unguessable from "backend unreachable".
		return Remote{Origin: OriginNone, Err: fmt.Errorf("%w; the cached config is unusable (%v); "+
			"collecting under local config only. Delete %s to clear it", fetchErr, err, CacheFile)}
	}
	return Remote{Origin: OriginCached, Doc: doc, Expired: cached.Expired(o.Now), Err: fetchErr}
}

func fetch(ctx context.Context, o RefreshOptions) (Remote, error) {
	c, err := o.Enrollment.Client()
	if err != nil {
		return Remote{}, err
	}
	doc, resp, err := c.FetchConfig(ctx, ConfigRequest{
		AgentVersion:   platform.Current().String(),
		ConfigVersions: config.AcceptedConfigVersions,
	})
	if err != nil {
		return Remote{}, err
	}
	fresh := Cached{CacheSchema: cacheSchema, Config: resp.Config, FetchedAt: o.Now, ExpiresAt: resp.ExpiresAt}
	if err := platform.WriteJSON(filepath.Join(o.StateDir, CacheFile), fresh, 0o600); err != nil {
		return Remote{}, err
	}
	// A server handing out an already-expired config is misbehaving, and the flag says so.
	return Remote{Origin: OriginFetched, Doc: doc, Expired: fresh.Expired(o.Now)}, nil
}

// CacheFile holds the last remote config fetched, so a run with no reachable backend still has a remote layer.
const CacheFile = "remote-config.json"

// cacheSchema versions the file; an older cache counts as none until the next fetch rewrites it.
const cacheSchema = 3

// Cached keeps the served document verbatim, reparsed on load.
type Cached struct {
	CacheSchema int       `json:"cache_schema"`
	Config      []byte    `json:"config"`
	FetchedAt   time.Time `json:"fetched_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// LoadCache reads the cached config; the caller treats any error, a missing file included, as "no remote layer".
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

// Expired does NOT stop collection: the scope kept was already served, while halting would lose data for good.
func (c Cached) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt)
}
