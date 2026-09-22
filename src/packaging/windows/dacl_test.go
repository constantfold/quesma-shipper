package windows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sidInstaller          = "S-1-5-21-2214759596-1652326523-2275886453-1001"
	sidUsers              = "S-1-5-32-545"
	sidAuthenticatedUsers = "S-1-5-11"
	sidInteractive        = "S-1-5-4"
)

// The masks an ACL listing reports: ReadAndExecute, inherit-only generic read/execute, Modify, FullControl.
const (
	maskReadExecute        = 0x001200A9
	maskGenericReadExecute = 0xA0000000
	maskModify             = 0x001301BF
	maskFullControl        = 0x001F01FF
)

// The first fixtures are real directories' DACLs, so a rule change has to argue with the paths users pick.
func TestUntrustedWritersJudgesRealDirectoryLayouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		aces []ace
		want []string
	}{
		{
			name: `%LOCALAPPDATA%\Programs\Quesma Shipper`,
			aces: []ace{
				{SID: sidLocalSystem, Mask: maskFullControl, Allow: true},
				{SID: sidAdministrators, Mask: maskFullControl, Allow: true},
				{SID: sidInstaller, Mask: maskFullControl, Allow: true},
			},
		},
		{
			// CREATOR OWNER's GENERIC_ALL is inherit-only, on a directory only an administrator can create in.
			name: `C:\Program Files`,
			aces: []ace{
				{SID: sidUsers, Mask: maskGenericReadExecute, Allow: true, InheritOnly: true},
				{SID: sidUsers, Mask: maskReadExecute, Allow: true},
				{SID: sidCreatorOwner, Mask: genericAll, Allow: true, InheritOnly: true},
				{SID: sidAdministrators, Mask: maskFullControl, Allow: true},
			},
		},
		{
			// AppendData on a directory is CreateDirectories, which is why any user can mkdir at C:\.
			name: `C:\`,
			aces: []ace{
				{SID: sidAuthenticatedUsers, Mask: fileAppendData, Allow: true},
				{SID: sidAuthenticatedUsers, Mask: genericWrite | standardDelete, Allow: true, InheritOnly: true},
				{SID: sidAdministrators, Mask: maskFullControl, Allow: true},
			},
			want: []string{sidAuthenticatedUsers},
		},
		{
			// INTERACTIVE matches every logged-on account.
			name: `C:\Users\Public`,
			aces: []ace{
				{SID: sidCreatorOwner, Mask: maskFullControl, Allow: true},
				{SID: sidInteractive, Mask: maskModify, Allow: true},
				{SID: sidInteractive, Mask: maskReadExecute, Allow: true},
			},
			want: []string{sidInteractive},
		},
		{
			name: "NULL DACL, which grants everyone full access",
			aces: []ace{{SID: sidEveryone, Mask: genericAll, Allow: true}},
			want: []string{sidEveryone},
		},
		{
			name: "denied and read-only access",
			aces: []ace{
				{SID: sidUsers, Mask: maskFullControl, Allow: false},
				{SID: sidUsers, Mask: maskReadExecute, Allow: true},
				{SID: sidInteractive, Mask: maskGenericReadExecute, Allow: true},
			},
		},
		{
			// A case-sensitive SID comparison would report the installer as a threat to their own directory.
			name: "the installer in lower case",
			aces: []ace{{SID: strings.ToLower(sidInstaller), Mask: maskFullControl, Allow: true}},
		},
		{
			name: "each trustee reported once",
			aces: []ace{
				{SID: sidUsers, Mask: fileWriteData, Allow: true},
				{SID: sidUsers, Mask: standardWriteOwner, Allow: true},
				{SID: sidInteractive, Mask: maskModify, Allow: true},
			},
			want: []string{sidUsers, sidInteractive},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := untrustedWriters(tc.aces, sidInstaller)
			require.Equalf(t, strings.Join(tc.want, ","), strings.Join(got, ","), "untrustedWriters() = %v, want %v", got, tc.want)
		})
	}
}

// Every composite right a user sees in an ACL listing has to intersect the atomic write bits.
func TestWriteMaskCoversTheCompositeRights(t *testing.T) {
	for name, mask := range map[string]uint32{
		"Modify":         maskModify,
		"FullControl":    maskFullControl,
		"GenericWrite":   genericWrite,
		"GenericAll":     genericAll,
		"TakeOwnership":  standardWriteOwner,
		"ChangePermsDAC": standardWriteDAC,
	} {
		assert.NotEqualf(t, uint32(0), mask&writeMask, "%s (%#08x) does not intersect writeMask", name, mask)
	}
	assert.Truef(t, maskReadExecute&writeMask == 0, "ReadAndExecute (%#08x) intersects writeMask", maskReadExecute)
	assert.Truef(t, maskGenericReadExecute&writeMask == 0, "GENERIC_READ|GENERIC_EXECUTE (%#08x) intersects writeMask", maskGenericReadExecute)
}
