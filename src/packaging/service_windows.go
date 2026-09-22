//go:build windows

package packaging

import (
	"context"
	"errors"

	windowspkg "github.com/QuesmaOrg/quesma-shipper/packaging/windows"
)

func InstallService(spec ServiceSpec) (ServiceStatus, error) { return windowspkg.InstallService(spec) }
func UninstallService() (ServiceKind, error) {
	return serviceWindowsTask, windowspkg.UninstallService()
}
func serviceState(ctx context.Context) ServiceStatus  { return windowspkg.ServiceState(ctx) }
func RestartService(ctx context.Context) error        { return windowspkg.RestartService(ctx) }
func RestartCommand() string                          { return windowspkg.RestartCommand() }
func RemoveProgram(executable string) (string, error) { return windowspkg.RemoveProgram(executable) }
func SameProgram(a, b string) bool                    { return windowspkg.SameProgram(a, b) }
func ProgramRemovalDeferred() bool                    { return windowspkg.ProgramRemovalDeferred() }
func RemovalUnverified(err error) bool {
	return errors.Is(err, windowspkg.ErrTaskDeleteUnverified)
}
