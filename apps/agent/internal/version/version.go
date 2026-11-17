// Package version holds build-time version information injected via -ldflags.
package version

// These are overridden at build time:
//
//	-ldflags "-X github.com/ppanel/ppanel/apps/agent/internal/version.Version=0.1.0"
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// ProtocolVersion is the agent<->center protocol major version (X-Agent-Protocol header).
const ProtocolVersion = "1"
