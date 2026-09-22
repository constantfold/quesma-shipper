package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

const (
	updateCheckTimeout = 5 * time.Second
	NoSelfUpdateEnv    = "SHIPPER_NO_SELFUPDATE"
	ReexecGuardEnv     = "SHIPPER_SELFUPDATE_REEXEC"
)

type UpdateStatus struct {
	State     string // disabled | skipped | failed | available | current
	Latest    string
	Published time.Time
	Detail    string
	Fix       string // the exact command, rendered as an arrow line under the header
}

func checkUpdate(ctx context.Context, build Build, autoupdate bool, getenv func(string) string,
	check func(context.Context, packaging.UpdateOptions) (string, time.Time, bool, error)) UpdateStatus {
	if getenv(NoSelfUpdateEnv) != "" {
		return UpdateStatus{State: "disabled", Detail: "check disabled by " + NoSelfUpdateEnv}
	}
	if !autoupdate {
		return UpdateStatus{State: "disabled", Detail: "check disabled by autoupdate.enabled: false"}
	}
	// Only a release build self-updates, through TUF; a dev build makes no network call.
	if !build.Release {
		return UpdateStatus{State: "skipped", Detail: "dev build; self-update installs only in release builds"}
	}
	latest, published, available, err := check(ctx, packaging.UpdateOptions{Current: build.Version, Timeout: updateCheckTimeout})
	when := ""
	if !published.IsZero() {
		when = ", " + published.Format(time.DateOnly)
	}
	switch {
	case err != nil:
		return UpdateStatus{State: "failed", Detail: fmt.Sprintf("check failed - %v", err)}
	case available:
		return UpdateStatus{State: "available", Latest: latest, Published: published,
			Detail: fmt.Sprintf("%s available (%s)", latest, published.Format("2006-01-02")),
			Fix:    "quesma-shipper update"}
	default:
		return UpdateStatus{State: "current", Latest: latest, Published: published,
			Detail: fmt.Sprintf("up to date (newest release is %s%s)", latest, when)}
	}
}

func HomeTilde(path string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}

func controlPlaneRows(enr *controlplane.Enrollment, enrErr error,
	eff *config.Effective, remote controlplane.Remote) []Row {
	if enr == nil {
		if enrErr != nil && !errors.Is(enrErr, os.ErrNotExist) {
			return []Row{{Sev: SevWarn, Label: "server",
				Detail: fmt.Sprintf("enrollment record unreadable: %v", enrErr),
				Fix:    "the install behaves as standalone until this is fixed"}}
		}
		return nil
	}
	var rows []Row
	if remote.Err != nil {
		rows = append(rows, Row{Sev: SevWarn, Label: "server", Brief: "server unreachable",
			Detail: fmt.Sprintf("unreachable, running on cached settings: %v", remote.Err),
			Fix:    "collecting continues, settings changes wait until it answers"})
	} else {
		rows = append(rows, Row{Sev: SevOK, Label: "server",
			Detail: "connected, settings current"})
	}
	if remote.Expired || eff.ConfigExpired {
		rows = append(rows, Row{Sev: SevWarn, Label: "server", Brief: "cached settings expired",
			Detail: "cached settings are past their expiry, still collecting",
			Fix:    "check that the server is reachable"})
	}
	return rows
}

func enrollmentRows(stateDir string, enr *controlplane.Enrollment, enrErr error,
	eff *config.Effective, remote controlplane.Remote) []Row {
	if enr == nil {
		if enrErr == nil || errors.Is(enrErr, os.ErrNotExist) {
			return []Row{{Sev: SevDim, Label: "enrollment",
				Detail: "standalone - no endpoint configured; no control-plane calls"}}
		}
		return []Row{{Sev: SevWarn, Label: "enrollment", Detail: fmt.Sprintf("unreadable: %v", enrErr)}}
	}

	rows := []Row{
		{Sev: SevDim, Label: "enrollment", Detail: fmt.Sprintf("%s - organization %s", enr.Endpoint, enr.Organization)},
	}
	if root, err := formats.InstallRoot(enr.Organization, enr.InstallID); err == nil {
		rows = append(rows, Row{Sev: SevDim, Label: "install_key_root", Detail: root})
	}

	cached := Row{Sev: SevDim, Label: "cached_config", Detail: "none - no remote config has verified yet"}
	if c, err := controlplane.LoadCache(stateDir); err == nil {
		fetched, expires := c.FetchedAt.Format(time.RFC3339), c.ExpiresAt.Format(time.RFC3339)
		cached.Sev, cached.Detail = SevOK, fmt.Sprintf("current - fetched %s, expires %s", fetched, expires)
		if c.Expired(time.Now()) {
			cached.Sev, cached.Detail = SevWarn, fmt.Sprintf("expired - fetched %s, expired %s", fetched, expires)
			cached.Fix = "collecting under it and stamping config_expired; check that the control plane is reachable"
		}
	}
	rows = append(rows, cached)

	rows = append(rows, Row{Sev: SevDim, Label: "config_source", Detail: string(remote.Origin)})
	if remote.Err != nil {
		rows = append(rows, Row{Sev: SevWarn, Label: "config_fetch",
			Detail: fmt.Sprintf("failed: %v", remote.Err),
			Fix:    "the run still collects under cached/local layers; a pushed policy change has not taken effect"})
	}
	if eff.ConfigExpired {
		rows = append(rows, Row{Sev: SevWarn, Label: "config_expired",
			Detail: "true - every manifest this run carries the stamp"})
	}
	return rows
}
