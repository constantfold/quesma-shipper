//go:build !darwin && !linux && !windows

package packaging

import (
	"context"
	"runtime"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

func UninstallService() (common.Kind, error) { return common.KindUnsupported, nil }
func serviceState(context.Context) ServiceStatus {
	return ServiceStatus{Kind: common.KindUnsupported, Detail: "no supervision mechanism on " + runtime.GOOS}
}
func RestartService(context.Context) error            { return nil }
func RestartCommand() string                          { return "" }
func RemoveProgram(executable string) (string, error) { return common.RemoveProgram(executable) }
