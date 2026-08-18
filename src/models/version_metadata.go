package models

import "time"

type VersionMetadata struct {
	Ecosystem     string        `json:"ecosystem"`
	PackageName   string        `json:"package_name"`
	Versions      []VersionInfo `json:"versions"`
	LatestVersion *VersionInfo  `json:"latest_version,omitempty"`
	CollectedAt   *time.Time    `json:"collected_at,omitempty"`
	Status        string        `json:"status"` // "success", "skip", "error"
	Message       string        `json:"message,omitempty"`
}

type VersionInfo struct {
	Version string `json:"version"`
	// ReleasedAt is nil when the registry publishes no release date for this
	// version. Maven Central is the case in point: its version index carries a
	// single timestamp for the whole artifact, not one per version. Callers must
	// report an absent date as unknown rather than treating it as the epoch.
	ReleasedAt *time.Time `json:"released_at,omitempty"`
}

// ReleasedAfter orders versions by release date, treating an unknown date as
// older than any known one so dated releases sort first.
func (v VersionInfo) ReleasedAfter(other VersionInfo) bool {
	if v.ReleasedAt == nil {
		return false
	}
	if other.ReleasedAt == nil {
		return true
	}
	return v.ReleasedAt.After(*other.ReleasedAt)
}
