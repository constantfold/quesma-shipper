package packaging

import (
	"context"
	"errors"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
	linuxpkg "github.com/QuesmaOrg/quesma-shipper/packaging/linux"
)

func detectService() common.Kind {
	if linuxpkg.Available() {
		return common.KindSystemd
	}
	return common.KindCron
}

func InstallService(spec common.Spec) error {
	if err := common.ValidateInstall(spec); err != nil {
		return err
	}
	if detectService() == common.KindCron {
		return ErrCronManual
	}
	return linuxpkg.InstallService(spec)
}

func UninstallService() (common.Kind, error) {
	if detectService() == common.KindCron {
		return common.KindCron, errors.New("supervise: nothing to remove: this host was never given a supervision entry, only a crontab line to add by hand")
	}
	return common.KindSystemd, linuxpkg.UninstallService()
}

func serviceState(ctx context.Context) ServiceStatus {
	if detectService() == common.KindCron {
		return ServiceStatus{Kind: common.KindCron, Detail: "no supervision entry: this host uses cron, which the client does not edit"}
	}
	return linuxpkg.ServiceState(ctx)
}

func RestartService(ctx context.Context) error        { return linuxpkg.RestartService(ctx) }
func RestartCommand() string                          { return linuxpkg.RestartCommand() }
func RemoveProgram(executable string) (string, error) { return common.RemoveProgram(executable) }
