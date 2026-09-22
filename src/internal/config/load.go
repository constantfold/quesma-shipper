package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// maxConfigBytes bounds a config file; anything larger is a mistake or an attempt to exhaust memory.
const maxConfigBytes = 1 << 20

// Paths locates the one config file and the state directory. The remote layer is absent on purpose: it needs enrollment.
type Paths struct {
	User     string
	StateDir string
}

// DefaultPaths returns the standard locations, honouring XDG where it applies.
func DefaultPaths(home string, lookup func(string) (string, bool)) Paths {
	xdg := func(name string, fallback ...string) string {
		if v, ok := lookup(name); ok && v != "" {
			return v
		}
		return filepath.Join(append([]string{home}, fallback...)...)
	}
	return Paths{
		User:     filepath.Join(xdg("XDG_CONFIG_HOME", ".config"), "trajectory-shipper", "config.yaml"),
		StateDir: filepath.Join(xdg("XDG_STATE_HOME", ".local", "state"), "trajectory-shipper"),
	}
}

// LoadLayers reads the user's config file. Missing is not an error (clone-and-run); present but unreadable or unparseable is,
// since skipping it would silently drop the whole layer.
func LoadLayers(p Paths) ([]LayeredDocument, error) {
	raw, _, err := platform.ReadWhole(p.User, maxConfigBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case errors.Is(err, platform.ErrNotRegular):
		return nil, fmt.Errorf("config: %s is not a regular file", p.User)
	case err != nil:
		return nil, fmt.Errorf("config: cannot read %s: %w", p.User, err)
	}
	doc, err := ParseDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", p.User, err)
	}
	return []LayeredDocument{{Layer: LayerUser, Doc: doc}}, nil
}

// UserConfigFound reports whether the user's config file exists, for `config show` and the startup log line.
func UserConfigFound(p Paths) (string, bool) {
	_, err := os.Stat(p.User)
	return p.User, err == nil
}
