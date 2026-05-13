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
	Version    string    `json:"version"`
	ReleasedAt time.Time `json:"released_at"`
}
