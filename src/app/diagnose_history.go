package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

type lastUpload struct {
	at       time.Time
	bySource map[string]engine.SourceHealth
}

func loadLastUpload(stateDir string) lastUpload {
	raw, err := os.ReadFile(filepath.Join(stateDir, engine.Name))
	if err != nil {
		return lastUpload{}
	}
	var hb engine.Heartbeat
	if err := json.Unmarshal(raw, &hb); err != nil {
		return lastUpload{}
	}
	at, err := time.Parse(time.RFC3339, hb.At)
	if err != nil {
		return lastUpload{}
	}
	up := lastUpload{at: at, bySource: map[string]engine.SourceHealth{}}
	for _, s := range hb.Sources {
		up.bySource[s.SourceID] = s
	}
	return up
}

type familyUpload struct {
	recorded        bool
	at              time.Time
	shipped, failed int
	pending         int
}

func familyUploadFor(probes []sourceProbe, up lastUpload) familyUpload {
	agg := familyUpload{at: up.at}
	for _, pr := range probes {
		agg.pending += pr.pending
		if s, ok := up.bySource[pr.src.ID]; ok {
			agg.recorded = true
			agg.shipped += s.Shipped
			agg.failed += s.Failed
		}
	}
	return agg
}

const fixSeeRunLog = "`quesma-shipper log` shows what each run did"

func scheduleRows(stateDir string, now time.Time) []Row {
	var rows []Row
	if p := platform.Read(stateDir); p.Paused {
		rows = append(rows, Row{Sev: SevWarn, Label: "collecting", Brief: "paused",
			Detail: "paused until " + FormatUntil(p.UntilTime(), now),
			Fix:    "`quesma-shipper resume`"})
	}

	rows = append(rows, failureRows(stateDir, now)...)

	st := packaging.ServiceState(stateDir)
	switch {
	case st.Loaded && st.LastRun.IsZero():
		rows = append(rows, Row{Sev: SevWarn, Label: "background service", Brief: "background service never ran",
			Detail: "loaded but it has never completed a run",
			Fix:    fixSeeRunLog})
	case st.Loaded:
		rows = append(rows, Row{Sev: SevOK, Label: "background service",
			Detail: "running"})
	case st.Installed:
		rows = append(rows, Row{Sev: SevWarn, Label: "background service", Brief: "background service not loaded",
			Detail: "installed but not loaded",
			Fix:    "re-run the Quesma Shipper installer"})
	default:
		rows = append(rows, Row{Sev: SevWarn, Label: "background service", Brief: "no background service",
			Detail: "not installed, nothing is sent on its own",
			Fix:    "re-run the Quesma Shipper installer"})
	}
	return rows
}

// A loaded service whose every tick fails looks identical to a healthy one from the outside.
func failureRows(stateDir string, now time.Time) []Row {
	rec := readFailureRecord(stateDir)
	if rec.ConsecutiveFailures == 0 {
		return nil
	}
	detail := "the last " + CountNoun(rec.ConsecutiveFailures, "run") + " failed, so nothing has been sent since"
	fix := fixSeeRunLog
	// Counted, not merely newest: an uncounted event would blame the streak on the wrong thing.
	if last := rec.LatestCounted(); last != nil {
		if at, err := time.Parse(time.RFC3339, last.At); err == nil {
			detail += ", most recently " + Ago(at, now)
		}
		fix = last.Message
	}
	return []Row{{Sev: SevWarn, Label: "recent runs", Brief: "recent runs are failing",
		Detail: detail, Fix: fix}}
}

// lastFailureRows adds recovered failures to verbose output; scheduleRows already reports an ongoing streak.
func lastFailureRows(stateDir string, now time.Time, verbose bool) []Row {
	if !verbose {
		return nil
	}
	rec := readFailureRecord(stateDir)
	if rec.ConsecutiveFailures > 0 {
		return nil
	}
	latest := rec.Latest()
	if latest == nil {
		return nil
	}
	at, _ := time.Parse(time.RFC3339, latest.At)
	detail := fmt.Sprintf("%s, %s: %s", Ago(at, now), latest.Kind, latest.Message)
	return []Row{{Sev: SevDim, Label: "last failure", Detail: detail}}
}
