package config

import "fmt"

// Layer is one step of the precedence chain; env vars are deliberately not one, so nothing the resolver enforces can be moved by one.
type Layer int

const (
	LayerCompiledDefaults Layer = iota + 1 // the binary's own defaults: the scope ceiling
	LayerBundledCatalog                    // the embedded source-spec catalog, compiled in
	LayerUser                              // the per-user config file, the machine owner's own
	LayerRemote                            // the org's served document, present only when enrolled
)

// IsLocal reports whether a layer is under the machine owner's control: where a deny beats a remote allow.
func (l Layer) IsLocal() bool {
	return l >= LayerCompiledDefaults && l <= LayerUser
}

func (l Layer) String() string {
	if l >= LayerCompiledDefaults && l <= LayerRemote {
		return [...]string{"compiled-defaults", "bundled-catalog", "user", "remote"}[l-1]
	}
	return fmt.Sprintf("layer(%d)", int(l))
}
