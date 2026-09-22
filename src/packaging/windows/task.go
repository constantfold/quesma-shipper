// Package windows owns the interactive user’s Task Scheduler entry.
// The supervisor’s kill-on-close Job Object makes stops deterministic, not graceful.
// Interrupted files replay because upload confirmation precedes commit.
package windows

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

type Spec = common.Spec
type Status = common.Status

// legacyTaskName is the pre-per-user name; machine-wide, it let one user's install overwrite or block another's.
const legacyTaskName = `\Quesma Shipper`
const taskRunnerName = "quesma-shipper-supervisor.exe"

// taskName suffixes the SID, not the account name, which can repeat across domains.
func taskName(userSID string) string { return legacyTaskName + " - " + userSID }

func taskRunner(executable string) string {
	dir := executable[:strings.LastIndexAny(executable, `\/`)+1]
	return dir + taskRunnerName
}

func programFromTask(command string) string {
	slash := strings.LastIndexAny(command, `\/`)
	base := command[slash+1:]
	if strings.EqualFold(base, taskRunnerName) {
		return command[:slash+1] + "quesma-shipper.exe"
	}
	return command
}

// renderTask points at the stable runner so every TUF replacement remains under Task Scheduler.
func renderTask(spec Spec, userSID, userName string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Collect local AI-agent trajectories, scrub and encrypt them, and send them to your organisation. Installed for %s.</Description>
    <URI>%s</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
      <UserId>%s</UserId>
      <Repetition>
        <Interval>PT1H</Interval>
      </Repetition>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT15M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>"%s"</Arguments>
    </Exec>
  </Actions>
</Task>
`, common.XMLText(userName), common.XMLText(taskName(userSID)), common.XMLText(userSID), common.XMLText(userSID),
		common.XMLText(taskRunner(spec.Executable)), common.XMLText(spec.LogDir))
}

type taskDocument struct {
	Enabled *bool  `xml:"Settings>Enabled"`
	Command string `xml:"Actions>Exec>Command"`
	UserID  string `xml:"Principals>Principal>UserId"`
}

// enabled: Task Scheduler omits a setting left at its default, so an absent Settings/Enabled means enabled.
func (d taskDocument) enabled() bool {
	return d.Enabled == nil || *d.Enabled
}

// legacyTaskIsOurs: another user's pre-rename task is neither ours to retire nor deletable.
func legacyTaskIsOurs(doc taskDocument, userSID string) bool {
	return doc.UserID != "" && strings.EqualFold(doc.UserID, userSID)
}

func parseTask(raw []byte) (taskDocument, error) {
	raw = taskXMLUTF8(raw)
	var doc taskDocument
	err := xml.Unmarshal(raw, &doc)
	return doc, err
}

// taskXMLForSchtasks emits the Unicode file format expected by schtasks /Create /XML.
func taskXMLForSchtasks(raw string) []byte {
	encoded := []byte{0xff, 0xfe}
	for _, unit := range utf16.Encode([]rune(strings.Replace(raw, `encoding="UTF-8"`, `encoding="UTF-16"`, 1))) {
		encoded = binary.LittleEndian.AppendUint16(encoded, unit)
	}
	return encoded
}

// taskXMLUTF8 accepts schtasks' UTF-16 with a BOM and its single-byte text declaring UTF-16; NULs tell them apart.
func taskXMLUTF8(raw []byte) []byte {
	switch {
	case len(raw) >= 2 && raw[0] == 0xff && raw[1] == 0xfe:
		raw = decodeUTF16LE(raw[2:])
	case bytes.IndexByte(raw[:min(len(raw), 64)], 0) >= 0:
		raw = decodeUTF16LE(raw)
	}
	raw = bytes.Replace(raw, []byte(`encoding="UTF-16"`), []byte(`encoding="UTF-8"`), 1)
	return bytes.Replace(raw, []byte(`encoding="utf-16"`), []byte(`encoding="UTF-8"`), 1)
}

func decodeUTF16LE(raw []byte) []byte {
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	return []byte(string(utf16.Decode(units)))
}
