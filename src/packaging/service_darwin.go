package packaging

import (
	"context"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
	"github.com/QuesmaOrg/quesma-shipper/packaging/macos"
)

func UninstallService() (common.Kind, error)          { return common.KindLaunchd, macos.UninstallService() }
func serviceState(ctx context.Context) ServiceStatus  { return macos.ServiceState(ctx) }
func RestartService(ctx context.Context) error        { return macos.RestartService(ctx) }
func RestartCommand() string                          { return macos.RestartCommand() }
func RemoveProgram(executable string) (string, error) { return macos.RemoveProgram(executable) }
func PostInstall() error                              { return macos.PostInstall() }
func updateTarget(release common.Release) string      { return macos.UpdateTarget(release) }
func applyTarget(raw []byte, version string) error    { return macos.ApplyTarget(raw, version) }
