// The collecting verbs' entry into the crash journal: report how the previous run died, then
// mark this one's start. Best-effort throughout — a broken journal must never stop shipping.
package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/crashjournal"
)

// startCrashJournal opens the journal in dir; dirErr says the caller could not find one, which
// leaves this run unjournaled rather than unstarted.
func startCrashJournal(errOut io.Writer, dir string, dirErr error) (*crashjournal.Log, string, *formats.LastCrash) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	runID := hex.EncodeToString(b)
	if dirErr != nil {
		return nil, runID, nil
	}
	prev := crashjournal.LastRun(dir) // before Open, which may rotate the file this reads

	fl, err := crashjournal.Open(dir, runID)
	if err != nil {
		fmt.Fprintf(errOut, "warning: crash journal unavailable: %v\n", err)
		return nil, runID, nil
	}
	fl.Start()

	if prev == nil {
		return fl, runID, nil
	}
	crash := &formats.LastCrash{RunID: prev.RunID, Phase: prev.Phase, Consecutive: prev.Crashes}
	fmt.Fprintf(errOut, "previous run %s never exited: last step %q; %d consecutive unclean run(s)\n",
		prev.RunID, prev.Phase, prev.Crashes)
	app.RecordCrash(crash)
	return fl, runID, crash
}
