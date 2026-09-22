// Install-directory guard. Task Scheduler starts the program in the installing user's session, so
// write access to that directory is the ability to run code as that user: an install target another
// non-admin can change is refused. The decision runs on any host; dacl_windows.go reads real DACLs.

package windows

import "strings"

// Win32 write access-mask bits, named here so the decision logic carries no build tag.
const (
	fileWriteData       = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	fileAppendData      = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	fileWriteEA         = 0x00000010 // FILE_WRITE_EA
	fileDeleteChild     = 0x00000040 // FILE_DELETE_CHILD
	fileWriteAttributes = 0x00000100 // FILE_WRITE_ATTRIBUTES
	standardDelete      = 0x00010000 // DELETE
	standardWriteDAC    = 0x00040000 // WRITE_DAC
	standardWriteOwner  = 0x00080000 // WRITE_OWNER
	genericAll          = 0x10000000 // GENERIC_ALL
	genericWrite        = 0x40000000 // GENERIC_WRITE
)

// Testing the atomic bits also catches the composite rights: Modify and FullControl are supersets.
const writeMask = fileWriteData | fileAppendData | fileWriteEA | fileDeleteChild |
	fileWriteAttributes | standardDelete | standardWriteDAC | standardWriteOwner |
	genericAll | genericWrite

const (
	accessAllowedACEType = 0x00 // ACE_HEADER.AceType
	inheritOnlyACE       = 0x08 // ACE_HEADER.AceFlags: describes children, not this object
)

// Trustees whose write access is no finding: platform identities, and CREATOR OWNER, which resolves to the creator.
const (
	sidLocalSystem      = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidCreatorOwner     = "S-1-3-0"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// sidEveryone stands in for a NULL DACL, which grants every account full access.
const sidEveryone = "S-1-1-0"

type ace struct {
	SID         string
	Mask        uint32
	Allow       bool
	InheritOnly bool
}

// untrustedWriters ignores deny entries rather than subtracting them: over-reporting is the safe direction.
func untrustedWriters(aces []ace, installerSID string) []string {
	var found []string
	seen := make(map[string]bool, len(aces))
	for _, a := range aces {
		if !a.Allow || a.InheritOnly || a.Mask&writeMask == 0 {
			continue
		}
		if trustedTrustee(a.SID, installerSID) || seen[a.SID] {
			continue
		}
		seen[a.SID] = true
		found = append(found, a.SID)
	}
	return found
}

func trustedTrustee(sid, installerSID string) bool {
	switch sid {
	case sidLocalSystem, sidAdministrators, sidCreatorOwner, sidTrustedInstaller:
		return true
	}
	return installerSID != "" && strings.EqualFold(sid, installerSID)
}
