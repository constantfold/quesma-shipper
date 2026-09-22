package app

import (
	"fmt"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

const (
	Name    = "quesma-shipper"
	AuthEnv = "SHIPPER_AUTH_KEY"
)

// Build describes this binary; only a corroborated release stamp (Release) may self-update.
type Build struct {
	Version string
	Release bool
}

func NewBuild() Build {
	return Build{Version: platform.Current().String(), Release: platform.Current().Release}
}

func VersionLine(b Build) string {
	i := platform.Current()
	v := strings.TrimPrefix(b.Version, "v")
	if v == "" || v == "unknown" {
		v = i.Version
	}
	if !b.Release {
		v = "dev"
		if rev := platform.ShortRev(i.Revision); rev != "" {
			v += " " + rev
		}
	}
	return fmt.Sprintf("%s %s (%s %s)", Name, v, osName(i.OS), i.Arch)
}

func osName(goos string) string {
	switch goos {
	case "darwin":
		return "macOS"
	case "linux":
		return "Linux"
	}
	return goos
}
