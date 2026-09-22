package engine

import (
	"cmp"
	"context"
	"os/user"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/identity"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// Options configures one run: resolved policy, so the core never imports config, plus ports and hooks.
type Options struct {
	// OrganizationID is the organization= key segment; empty means the standalone placeholder.
	OrganizationID string
	StateDir       string
	MaxFilesPerRun int
	Interval       time.Duration
	Sources        []sources.Resolved
	RulePacks      []string
	SecretKeyNames []string
	StructuralEx   map[string][]string

	// Deny is required: a nil deny list would read as "nothing is denied". Nil Ignore ignores nothing.
	Deny          *sources.List
	Ignore        *sources.RepoFilter
	ConfigVersion int

	// ConfigExpired stamps every manifest. Expiry does not stop collection; it makes staleness visible.
	ConfigExpired bool

	Identity *identity.Unit
	Log      *auditlog.Log

	// Upload is the write path. Required for a run that ships; a preview seals without one.
	Upload     UploadPort
	Recipients []age.Recipient

	// Unbounded ignores max_files_per_run; set by the drain only.
	Unbounded bool

	// DryRun reads, scrubs and seals but neither uploads nor commits. This is `preview`.
	DryRun bool

	// Enrichers is the compiled registry. Nil disables enrichment.
	Enrichers transforms.Registry

	// Env expands an enricher's database candidates with the same ~ and $VAR rules as catalog roots.
	Env sources.Env

	// Heartbeat publishes discovery health after a run. Optional and best-effort: it fails open.
	Heartbeat func(context.Context, Report) error
	Progress  formats.Progress

	// RunID is the process's crash-journal id, stamped into every manifest this run seals.
	RunID string
	Now   func() time.Time

	// Test knobs, zero for defaults: fingerprints per state write, compute workers, PUTs in flight.
	CommitBatch   int
	Workers       int
	UploadWorkers int

	// Client is the build stamped into every manifest this run writes.
	Client transforms.Client

	// Set by Run: the path placeholder username, and the scrubber shared by raw and derived paths.
	user     string
	scrub    *transforms.Scrubber
	scrubErr error
}

// Aliased from the contract layer, so an adapter that needs these types does not import the core.
type (
	FileOutcome   = formats.FileOutcome
	SourceOutcome = formats.SourceOutcome
	Report        = formats.Report
)

func (o Options) scrubber() (*transforms.Scrubber, error) {
	cfg := transforms.DefaultConfig()
	cfg.RulePacks = o.RulePacks
	// Additive: configuration can only lengthen the compiled default list, never replace it.
	cfg.SecretKeyNames = append(cfg.SecretKeyNames, o.SecretKeyNames...)
	cfg.Exemptions = o.StructuralEx
	cfg.Username = o.user
	return transforms.New(cfg)
}

// org is the organization= key segment; the fallback keeps key depth constant.
func (o Options) org() string { return cmp.Or(o.OrganizationID, "default") }

// UsernameFromStateDir is the path placeholder's user, from the state dir so redaction and keys agree.
func UsernameFromStateDir(stateDir string) string {
	if name := formats.UsernameFromPath(stateDir); name != "" {
		return name
	}
	if u, err := user.Current(); err == nil {
		// Windows usernames come as HOST\name.
		if _, name, ok := strings.Cut(u.Username, `\`); ok {
			return name
		}
		return u.Username
	}
	return ""
}
