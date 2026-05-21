package version

import "runtime/debug"

// Version can be overridden at build time: go build -ldflags="-X risk-guard/src/version.Version=0.3.0"
var Version = "dev"

const CatalogVersion = "2024-10"

var (
	BuildTime    = "unknown"
	BuildGitHash = "unknown"
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if BuildGitHash == "unknown" || BuildGitHash == "" {
				BuildGitHash = s.Value
			}
		case "vcs.time":
			if BuildTime == "unknown" || BuildTime == "" {
				BuildTime = s.Value
			}
		}
	}
}

func GetBuildTime() string {
	return BuildTime
}

func GetBuildGitHash() string {
	return BuildGitHash
}
