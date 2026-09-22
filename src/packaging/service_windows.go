//go:build windows

package packaging

import (
	"context"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
	windowspkg "github.com/QuesmaOrg/quesma-shipper/packaging/windows"
)

func InstallService(spec common.Spec) error { return windowspkg.InstallService(spec) }
func UninstallService() (common.Kind, error) {
	return common.KindWindowsTask, windowspkg.UninstallService()
}
func serviceState(ctx context.Context) ServiceStatus  { return windowspkg.ServiceState(ctx) }
func RestartService(ctx context.Context) error        { return windowspkg.RestartService(ctx) }
func RestartCommand() string                          { return windowspkg.RestartCommand() }
func RemoveProgram(executable string) (string, error) { return windowspkg.RemoveProgram(executable) }
