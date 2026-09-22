package windows

import (
	"bytes"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

func TestTaskRunsAsTheInteractiveUserAndSurvivesUpdates(t *testing.T) {
	spec := Spec{
		Executable: `C:\Users\A & B\Quesma Shipper\quesma-shipper.exe`,
		LogDir:     `C:\Users\A & B\AppData\Local\quesma-shipper\logs`,
	}
	raw := renderTask(spec, "S-1-5-21-123", `WINDOWSSHIPPER\a & b`)

	for _, want := range []string{
		`<LogonType>InteractiveToken</LogonType>`,
		`<RunLevel>LeastPrivilege</RunLevel>`,
		`<URI>\Quesma Shipper - S-1-5-21-123</URI>`,
		`Installed for WINDOWSSHIPPER\a &amp; b.`,
		// Task Scheduler rejects a zero Duration; omitting it is what repeats indefinitely.
		"<Repetition>\n        <Interval>PT1H</Interval>\n      </Repetition>",
		`<RestartOnFailure>`,
		`C:\Users\A &amp; B\Quesma Shipper\quesma-shipper-supervisor.exe`,
		`<Arguments>"C:\Users\A &amp; B\AppData\Local\quesma-shipper\logs"</Arguments>`,
	} {
		assert.Containsf(t, raw, want, "task XML lacks %q:\n%s", want, raw)
	}
	require.NoError(t, xml.Unmarshal([]byte(raw), new(any)))
	doc, err := parseTask([]byte(raw))
	require.NoError(t, err)
	require.Truef(t, doc.enabled() && doc.Command == taskRunner(spec.Executable), "parsed task = %+v", doc)
}

// Windows 11 26200 writes single-byte text declaring UTF-16, with no BOM and a doubled CR.
func TestParseTaskAcceptsSingleByteOutputThatDeclaresUTF16(t *testing.T) {
	raw := "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\r\n" +
		`<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` +
		`<Settings><Enabled>true</Enabled></Settings>` +
		`<Principals><Principal id="Author"><UserId>S-1-5-21-7-1001</UserId></Principal></Principals>` +
		`<Actions><Exec><Command>C:\shipper.exe</Command></Exec></Actions></Task>`
	doc, err := parseTask([]byte(raw))
	require.NoError(t, err)
	require.Truef(t, doc.enabled() && doc.Command == `C:\shipper.exe`, "parsed task = %+v", doc)
	assert.True(t, legacyTaskIsOurs(doc, "S-1-5-21-7-1001"), "the principal did not survive the encoding fixup, so a legacy task cannot be retired")
}

// Task Scheduler omits a setting left at its default, so a live enabled task has no Settings/Enabled.
func TestParseTaskTreatsAnAbsentEnabledAsEnabled(t *testing.T) {
	raw := `<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` +
		`<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>` +
		`<StartWhenAvailable>true</StartWhenAvailable></Settings>` +
		`<Actions><Exec><Command>C:\shipper.exe</Command></Exec></Actions></Task>`
	doc, err := parseTask([]byte(raw))
	require.NoError(t, err)
	assert.True(t, doc.enabled(), "a task with no Settings/Enabled was reported as disabled")

	disabled := `<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` +
		`<Settings><Enabled>false</Enabled></Settings></Task>`
	doc, err = parseTask([]byte(disabled))
	require.NoError(t, err)
	assert.False(t, doc.enabled(), "an explicitly disabled task was reported as enabled")
}

func TestTaskXMLForSchtasksIsUTF16AndRoundTrips(t *testing.T) {
	raw := renderTask(common.Spec{Executable: `C:\Quesma Shipper\quesma-shipper.exe`}, "S-1-5-21-1", "jane")
	encoded := taskXMLForSchtasks(raw)
	require.True(t, bytes.HasPrefix(encoded, []byte{0xff, 0xfe}), "task XML lacks UTF-16LE BOM")
	doc, err := parseTask(encoded)
	require.NoError(t, err)
	assert.True(t, doc.enabled())
	assert.Equal(t, `C:\Quesma Shipper\quesma-shipper-supervisor.exe`, doc.Command)
}

func TestLegacyTaskIsOursOnlyForThisUsersOwnTask(t *testing.T) {
	ours := renderTask(common.Spec{Executable: `C:\shipper.exe`}, "S-1-5-21-7-1001", "jane")
	doc, err := parseTask([]byte(ours))
	require.NoError(t, err)
	assert.True(t, legacyTaskIsOurs(doc, "s-1-5-21-7-1001"), "a task whose principal is this user, in a different case, was not recognized")
	assert.False(t, legacyTaskIsOurs(doc, "S-1-5-21-7-1002"), "another user's task was treated as ours to retire")
	assert.False(t, legacyTaskIsOurs(taskDocument{}, "S-1-5-21-7-1001"), "a task with no principal was treated as ours to retire")
}

func TestTaskRunnerMapsBackToTheOwnedProgram(t *testing.T) {
	require.Equal(t, `C:\Users\Jane\Quesma Shipper\quesma-shipper.exe`,
		programFromTask(`C:\Users\Jane\Quesma Shipper\QUESMA-SHIPPER-SUPERVISOR.EXE`))
}
