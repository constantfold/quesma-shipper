//go:build unix

package app

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// An unwritable record must survive in memory, reach telemetry, and persist when the disk recovers.
func TestUnwrittenFailureSurvivesTelemetryAndRecovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	r := &Runtime{eff: &config.Effective{StateDir: dir}}
	require.NoError(t, os.Chmod(dir, 0o500))
	defer os.Chmod(dir, 0o700)
	r.JudgeTick(errors.New("state: no space left on device"), formats.Report{}, false, platform.Delta{})

	rec := r.failureRecord()
	require.Truef(t, rec.Latest() != nil && strings.Contains(rec.Latest().Message, "no space left"), "the unwritable failure did not survive in memory: %+v", rec)
	assert.Equalf(t, 1, rec.ConsecutiveFailures, "consecutive_failures = %d, want 1", rec.ConsecutiveFailures)
	disk := readFailureRecord(dir)
	require.Nil(t, disk.Latest(), "the read-only state dir somehow took a write")

	for _, recovered := range []bool{false, true} {
		wantCount := 1
		if recovered {
			require.NoError(t, os.Chmod(dir, 0o700))
			r.JudgeTick(nil, formats.Report{Shipped: 1}, false, platform.Delta{})
			wantCount = 0
		}
		_, body, err := r.installHealth(time.Now())
		require.NoError(t, err)
		var event telemetryEvent
		require.NoError(t, json.Unmarshal(body, &event))
		require.Truef(t, event.Consecutive == wantCount && len(event.Faults) == 1 && strings.Contains(event.Faults[0].Message, "no space left"), "recovered=%v: telemetry lost the failure or its recovery: %+v", recovered, event)
	}
	disk = readFailureRecord(dir)
	assert.Truef(t, disk.ConsecutiveFailures == 0 && disk.Latest() != nil, "recovery did not persist the retained failure: %+v", disk)
}
