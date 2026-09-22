//go:build linux || windows

package app

import (
	"errors"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

// PostInstallPackage registers the installed program with the per-user supervisor.
func PostInstallPackage() (string, error) {
	eff, paths, err := ResolveEffective()
	if err != nil {
		return "", err
	}
	tick, warning := config.TickInterval(eff.Schedule)
	spec, err := packaging.NewServiceSpec(paths.StateDir, eff.DrainDeadline, tick)
	if err != nil {
		return warning, err
	}
	err = packaging.InstallService(spec)
	if errors.Is(err, packaging.ErrCronManual) {
		if warning != "" {
			warning += "\n"
		}
		return warning + "no background service; add this with `crontab -e`: " + packaging.CronHint(spec), nil
	}
	return warning, err
}
