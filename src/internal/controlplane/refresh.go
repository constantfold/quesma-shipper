package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
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

// Refresh caches a fetch that parses; ANY failure falls back to the last fetched config, expired or not, since a missed transcript is gone.
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
	doc, resp, err := c.FetchConfig(ctx, ConfigRequest{AgentVersion: platform.Current().String(), ConfigVersions: config.AcceptedConfigVersions})
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

const EnrollmentFile = "enrollment.json"

// enrollmentSchema: a newer record is refused, since guessing writes into the wrong subtree; an older one is migrated and persisted.
const enrollmentSchema = 2

// Enrollment lives beside the identity unit: without that identity it grants a subtree the client can no longer name.
type Enrollment struct {
	EnrollmentSchema int    `json:"enrollment_schema"`
	InstallID        string `json:"install_id"`
	Organization     string `json:"organization"`
	Endpoint         string `json:"endpoint"`
	DeviceKey        string `json:"device_key"` // private, so the file is 0600 and refused if looser
	EnrolledAt       string `json:"enrolled_at"`
}

func (e Enrollment) Save(stateDir string) error {
	e.EnrollmentSchema = enrollmentSchema
	return platform.WriteJSON(filepath.Join(stateDir, EnrollmentFile), e, 0o600)
}

// LoadEnrollment reads the record. A missing file means standalone and returns os.ErrNotExist.
func LoadEnrollment(stateDir string) (*Enrollment, error) {
	raw, err := platform.ReadPrivate(filepath.Join(stateDir, EnrollmentFile), 1<<20)
	if err != nil {
		return nil, err
	}
	var e Enrollment
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("backend: parse enrollment: %w", err)
	}
	// Schema 1 is schema 2 plus a sink grant, which decoding already dropped. The frozen fixture checks the conversion.
	if e.EnrollmentSchema == 1 {
		// Persisted immediately so the upgrade happens once and a downgraded binary refuses the record loudly.
		if err := e.Save(stateDir); err != nil {
			return nil, fmt.Errorf("backend: persist migrated enrollment: %w", err)
		}
		e.EnrollmentSchema = enrollmentSchema
	}
	if e.EnrollmentSchema != enrollmentSchema {
		return nil, fmt.Errorf("backend: enrollment_schema %d, this client speaks %d", e.EnrollmentSchema, enrollmentSchema)
	}
	return &e, nil
}

func (e Enrollment) PrivateKey() (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(e.DeviceKey)
	if err != nil {
		return nil, fmt.Errorf("backend: device key is not base64: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("backend: device key is %d bytes, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

func (e Enrollment) Client() (*Client, error) {
	key, err := e.PrivateKey()
	if err != nil {
		return nil, err
	}
	return New(Options{Endpoint: e.Endpoint, InstallID: e.InstallID, Organization: e.Organization, DeviceKey: key})
}

// EncodeKey is the wire and on-disk form of both key halves.
func EncodeKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }
