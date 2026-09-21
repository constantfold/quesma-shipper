// Package config merges configuration layers and records provenance.
// Local authority controls widening; compiled path denials and root checks still apply.
package config

// AcceptedConfigVersions is enumerated, never a range: an unknown config_version is a hard error.
var AcceptedConfigVersions = []int{1}
