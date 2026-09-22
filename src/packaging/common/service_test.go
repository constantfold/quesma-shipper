package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstallSpecRequiresAnAbsoluteExecutable(t *testing.T) {
	require.Error(t, ValidateInstall(Spec{Executable: "quesma-shipper"}), "a relative executable path was accepted")
	require.Error(t, ValidateInstall(Spec{}), "an empty spec was accepted")
}

// The hint is a one-shot run on the configured tick, rounded up to what cron can express.
func TestCronHint(t *testing.T) {
	spec := Spec{Executable: "/usr/local/bin/quesma-shipper", LogDir: "/Users/jane/logs", Tick: 5 * time.Minute}
	assert.Equal(t, "*/5 * * * * /usr/local/bin/quesma-shipper run --once >> /Users/jane/logs/cron.log 2>&1", CronHint(spec))
	for tick, want := range map[time.Duration]string{0: "*/15 * * * *", 30 * time.Second: "* * * * *",
		90 * time.Second: "*/2 * * * *", 25 * time.Hour: "0 0 * * *"} {
		assert.Equal(t, want, cronExpr(tick))
	}
}
