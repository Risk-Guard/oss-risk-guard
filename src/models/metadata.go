package models

import (
	"time"
)

// Maintainer represents a package maintainer/owner across all ecosystems
type Maintainer struct {
	Name                string     `json:"name,omitempty"`
	Email               string     `json:"email,omitempty"`
	Role                string     `json:"role,omitempty"` // "maintainer" (npm), "author"/"maintainer" (pypi), "owner" (rubygems)
	FirstPublishVersion *string    `json:"first_publish_version,omitempty"`
	FirstPublishDate    *time.Time `json:"first_publish_date,omitempty"`
	LastPublishVersion  *string    `json:"last_publish_version,omitempty"`
	LastPublishDate     *time.Time `json:"last_publish_date,omitempty"`
	VersionCount        int        `json:"version_count,omitempty"`
	IsActive            *bool      `json:"is_active,omitempty"`
}

func (m Maintainer) IsExplicitlyInactive() bool {
	return m.IsActive != nil && !*m.IsActive
}

// DistributionInfo contains artifact download and integrity information
type DistributionInfo struct {
	URL           string `json:"url,omitempty"`
	Filename      string `json:"filename,omitempty"`
	Hash          string `json:"hash,omitempty"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"` // "sha256", "sha512", "sha1"
}

// PackageMetadata represents package.yml - ecosystem package data
type PackageMetadata struct {
	Ecosystem    string            `json:"ecosystem"`
	PackageName  string            `json:"package_name"`
	Version      *string           `json:"version,omitempty"`
	Description  *string           `json:"description,omitempty"`
	Homepage     *string           `json:"homepage,omitempty"`
	SourceURL    *string           `json:"source_url,omitempty"`
	License      *string           `json:"license,omitempty"`
	ReleaseDate  *time.Time        `json:"release_date,omitempty"`
	Dependencies []Dependency      `json:"dependencies,omitempty"`
	Maintainers  []Maintainer      `json:"maintainers,omitempty"`
	Distribution *DistributionInfo `json:"distribution,omitempty"`
	Status       string            `json:"status"` // "success" | "skipped" | "error"
	CollectedAt  *time.Time        `json:"collected_at,omitempty"`
	StatusReason *string           `json:"status_reason,omitempty"`
}

func (p *PackageMetadata) HasLicense() bool {
	return p != nil && p.License != nil && *p.License != ""
}

// GitMetadata represents source/git.yml - git repository analysis
type GitMetadata struct {
	SourceURL              string     `json:"source_url"`
	Status                 string     `json:"status"` // "success" | "skipped" | "error"
	CollectedAt            *time.Time `json:"collected_at,omitempty"`
	StatusReason           *string    `json:"status_reason,omitempty"`
	RecentAuthorsCount     *int       `json:"recent_authors_count,omitempty"`
	MaxMonthlyAuthorsCount *int       `json:"max_monthly_authors_count,omitempty"`
	MaxMonthlyWindowStart  *time.Time `json:"max_monthly_window_start,omitempty"`
	MaxMonthlyWindowEnd    *time.Time `json:"max_monthly_window_end,omitempty"`
	FirstCommit            *time.Time `json:"first_commit,omitempty"`
	LatestHumanCommit      *time.Time `json:"latest_human_commit,omitempty"`
	CommitCount            *int       `json:"commit_count,omitempty"`
	HumanCommitCount       *int       `json:"human_commit_count,omitempty"`
}

// LicenseFile is a raw license-file candidate produced by the on-disk scanner
// before any SPDX matching. Path is relative to the repo root. File contents
// are deliberately not retained here — SPDX matching re-reads from the working
// tree — so that persisted artifacts don't duplicate license texts.
type LicenseFile struct {
	Path string `json:"path"`
}

// DependencyMetadata represents source/dependencies.yml
type DependencyMetadata struct {
	Status       string       `json:"status"` // "success" | "skipped" | "error"
	StatusReason *string      `json:"status_reason,omitempty"`
	Direct       []Dependency `json:"direct"`
	Transitive   []Dependency `json:"transitive,omitempty"`
	ParseErrors  []ParseError `json:"parse_errors,omitempty"`
}

// DynamicDependency tracks dependencies whose names cannot be statically
// determined at parse time. This occurs in Ruby (e.g., `gem "rack-#{version}"`,
// `s.add_dependency MyGem::NAME`) and Python setup.py (e.g., reading name from
// a file or using string formatting).
type DynamicDependency struct {
	SourceFile string `json:"source_file"`
	Line       int    `json:"line"`
	Reason     string `json:"reason"`
}

// ParseError represents a dependency file that failed to parse
type ParseError struct {
	FilePath  string `json:"file_path"`
	Error     string `json:"error"`
	ErrorType string `json:"error_type,omitempty"` // "read_error" | "parse_error"
}
