package engine

import (
	"context"
	"time"

	"filippo.io/age"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/identity"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// Options configures one run.
type Options struct {
	// Plan is what the loop needs from the configuration, and nothing else.
	Plan     Plan
	Identity *identity.Unit
	Log      *auditlog.Log

	// Upload is the write path. Required for a run that ships; a preview seals without one.
	Upload UploadPort

	// Recipients the object is encrypted to; an enterprise deployment adds org recipients.
	Recipients []age.Recipient

	// Unbounded ignores max_files_per_run. Set by the drain only; see Run.
	Unbounded bool

	// DryRun reads, scrubs and seals but neither uploads nor commits. This is `preview`.
	DryRun bool

	// Enrichers is the compiled registry. Nil disables enrichment.
	Enrichers transforms.Registry

	// Env expands an enricher's database candidates with the same ~ and $VAR rules as catalog roots.
	Env sources.Env

	// Heartbeat publishes discovery health after a run. Optional and best-effort: it fails open.
	Heartbeat func(context.Context, Report) error

	// Progress streams each file's outcome as it is decided. Optional; nil is silent.
	Progress formats.Progress

	// RunID is the process's crash-journal id, stamped into every manifest this run seals.
	RunID string

	// Now is injectable so tests are not timing-dependent.
	Now func() time.Time

	// CommitBatch bounds how many fingerprints buffer before the state document is replaced.
	// Zero takes the default; it is not configuration.
	CommitBatch int

	// Workers pins how many files a source pass computes at once. Zero takes GOMAXPROCS.
	Workers int

	// UploadWorkers pins how many PUTs are in flight at once. Zero takes eight times the
	// compute pool; see uploadConcurrency in pool.go.
	UploadWorkers int

	// Client is the build stamped into every manifest this run writes.
	Client transforms.Client

	// user is the placeholder username, set by Run before anything that reads it.
	user string

	// The run's compiled scrubber, shared by the raw and derived paths.
	scrub    *transforms.Scrubber
	scrubErr error
}

// The run's vocabulary lives in the contract layer, aliased here so an adapter that needs one
// of these types does not import the core.
type (
	FileOutcome   = formats.FileOutcome
	SourceOutcome = formats.SourceOutcome
	Report        = formats.Report
)

// Plan is the configuration the loop actually reads: every field is one it branches on. This
// keeps the core free of the config package and testable from a struct literal.
type Plan struct {
	// OrganizationID is the organization= key segment; empty means the standalone placeholder.
	OrganizationID string

	StateDir       string
	MaxFilesPerRun int
	Interval       time.Duration

	Sources []sources.Resolved

	// RulePacks and StructuralEx configure redaction; the scrub floor is an adapter's decision.
	RulePacks      []string
	SecretKeyNames []string
	StructuralEx   map[string][]string

	// Deny is the compiled path deny list. Required: a nil deny list would read as "nothing is denied".
	Deny *sources.List

	// Ignore drops candidates of an ignored repository. Nil is the ordinary state and
	// means nothing is ignored.
	Ignore *sources.RepoFilter

	ConfigVersion int

	// ConfigExpired stamps every manifest. Expiry does not stop collection; it makes staleness visible.
	ConfigExpired bool
}

func (o Options) scrubber() (*transforms.Scrubber, error) {
	cfg := transforms.DefaultConfig()
	cfg.RulePacks = o.Plan.RulePacks
	// Additive: configuration can only lengthen the compiled default list, never replace it.
	cfg.SecretKeyNames = append(cfg.SecretKeyNames, o.Plan.SecretKeyNames...)
	cfg.Exemptions = o.Plan.StructuralEx
	cfg.Username = o.user
	return transforms.New(cfg)
}

// orgOf is the organization= key segment, always the RESOLVED value: a hardcoded "default" splits
// one enrolled install across two organization subtrees. The fallback keeps key depth constant.
func orgOf(p Plan) string {
	if p.OrganizationID == "" {
		return "default"
	}
	return p.OrganizationID
}
