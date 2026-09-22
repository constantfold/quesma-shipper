package engine

import (
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// baseManifest fills the fields raw and derived objects share, so a wire-contract field added once
// cannot miss one path. The manifest is the only place a native path exists on the wire, so the
// username placeholder applies here too. Seal fills the hashes, size and recipient ids.
func (o Options) baseManifest(src sources.Resolved, nativePath, sourceHash string, res transforms.Result) transforms.Manifest {
	m := transforms.Manifest{
		ManifestVersion: transforms.ManifestVersion,
		OrganizationID:  orgOf(o.Plan),
		InstallID:       o.Identity.InstallID.String(),
		SourceID:        src.ID,
		SourceFamily:    src.Family,
		NativePath:      formats.ApplyUserPlaceholder(nativePath, o.user),
		Gather:          src.Gather,
		ArtifactClass:   src.ArtifactClass,
		SealedAt:        o.Now().Format(time.RFC3339),
		ConfigVersion:   o.Plan.ConfigVersion,
		ConfigExpired:   o.Plan.ConfigExpired,
		Client:          o.Client,
		RunID:           o.RunID,
		SourceHash:      sourceHash,
		ShapeSniff:      string(formats.SniffOK),
	}
	if src.Scrub == nil || *src.Scrub {
		m.Redaction = &transforms.RedactionSummary{Density: res.Density(), RuleHits: res.RuleHits}
	}
	return m
}

// mirrorKey is the key an object ships to. Path-derived, so a re-run lands on the same one.
func (o Options) mirrorKey(sourceID, relPath string) (string, error) {
	return formats.MirrorKey(orgOf(o.Plan), o.Identity.InstallID.String(), sourceID,
		o.Identity.NameKey, formats.CanonicalPath(relPath, o.user))
}
