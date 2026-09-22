//go:build linux || windows

package packaging

import (
	"time"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

type ServiceSpec = common.Spec

var ErrCronManual = common.ErrCronManual

// NewServiceSpec describes an agent run from this binary, resolved behind any installed symlink.
func NewServiceSpec(stateDir string, stopTimeout, tick time.Duration) (ServiceSpec, error) {
	exe, err := common.CurrentExecutable()
	if err != nil {
		return ServiceSpec{}, err
	}
	return common.ServiceSpecFor(exe, stateDir, stopTimeout, tick)
}

func CronHint(spec ServiceSpec) string { return common.CronHint(spec) }
