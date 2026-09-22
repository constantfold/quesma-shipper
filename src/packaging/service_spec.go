//go:build linux || windows

package packaging

import (
	"time"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

var ErrCronManual = common.ErrCronManual

// NewServiceSpec describes an agent run from this binary, resolved behind any installed symlink.
func NewServiceSpec(stateDir string, stopTimeout, tick time.Duration) (common.Spec, error) {
	exe, err := common.CurrentExecutable()
	if err != nil {
		return common.Spec{}, err
	}
	return common.ServiceSpecFor(exe, stateDir, stopTimeout, tick)
}

func CronHint(spec common.Spec) string { return common.CronHint(spec) }
