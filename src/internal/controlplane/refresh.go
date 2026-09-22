package controlplane

import (
	"context"
	"errors"
	"fmt"
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

// Remote is the resolved remote layer: the org's config, which enters the resolver as an ordinary document layer.
type Remote struct {
	Origin Origin
	Doc    *config.Document // nil when Origin is OriginNone

	// Expired is true when a config past its expiry is in use; it does not stop collection.
	Expired bool

	// Err is why a fetch did not happen or was refused. Reported, never swallowed: a quiet fallback
	// leaves an operator believing a config change took effect.
	Err error
}

// RefreshOptions configures a refresh.
type RefreshOptions struct {
	Enrollment *Enrollment
	StateDir   string
	Now        time.Time

	// Offline resolves from the cache: `config show` must explain the config in force without a round-trip that changes it.
	Offline bool
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

	// A cache that no longer parses is damage like any other unreadable file: local config only, the run continues.
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

// fetch does one round-trip and caches what it gets.
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
	fresh := Cached{Config: resp.Config, FetchedAt: o.Now, ExpiresAt: resp.ExpiresAt}
	if err := SaveCache(o.StateDir, fresh); err != nil {
		return Remote{}, err
	}
	// A server handing out an already-expired config is misbehaving, and the flag says so.
	return Remote{Origin: OriginFetched, Doc: doc, Expired: fresh.Expired(o.Now)}, nil
}
