// Package catalogdata embeds the bundled source-spec files as data. It carries the scope
// ceiling: coverage inside a compiled root family is a data-file change, a new root needs a
// release. No resolution happens here (env, globs, deny lists); that is the config layer.
package catalogdata

import "embed"

//go:embed *.yaml
var FS embed.FS
