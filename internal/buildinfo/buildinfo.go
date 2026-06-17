// Package buildinfo holds version metadata stamped into the binary at build
// time. Values are overridden by the linker via -ldflags -X (see .goreleaser.yml);
// the defaults below are what you get from a plain `go build` / `go install`.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

var (
	// Version is the semantic version, e.g. "1.2.3". Set by goreleaser.
	Version = "dev"
	// Commit is the git SHA the binary was built from.
	Commit = "none"
	// Date is the build timestamp (RFC3339).
	Date = "unknown"
)

// String returns a human-readable one-line version summary.
func String() string {
	v := Version
	// When installed via `go install ...@vX.Y.Z`, goreleaser ldflags are not
	// applied — recover the version from the module's build info instead.
	if v == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
	}
	// Normalize to a bare version: goreleaser stamps "0.2.0" while a module
	// build records "v0.2.0". Strip the leading "v" so callers can format it
	// consistently (e.g. "ironrun 0.2.0", never "ironrun vv0.2.0").
	return strings.TrimPrefix(v, "v")
}
