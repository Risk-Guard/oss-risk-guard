package models

import (
	"time"
)

type MetadataRoot struct {
	Version     string             `json:"version"`
	CollectedAt time.Time          `json:"collected_at"`
	Package     MetadataPackageRef `json:"package"`
}

// MetadataPackageRef contains package identification info
type MetadataPackageRef struct {
	Ecosystem string  `json:"ecosystem"`
	Name      string  `json:"name"`
	SourceURL *string `json:"source_url,omitempty"`
}

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

// PackageDestination represents a package defined in the source code
type PackageDestination struct {
	Ecosystem      string   `json:"ecosystem"`
	Name           string   `json:"name"`
	SourceFile     string   `json:"source_file"`
	IsDynamic      bool     `json:"is_dynamic,omitempty"`
	DynamicReason  *string  `json:"dynamic_reason,omitempty"`
	InstallScripts []string `json:"install_scripts,omitempty"`
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

// LicenseMetadata represents source/licenses.yml
type LicenseMetadata struct {
	Status            string             `json:"status"` // "success" | "skipped" | "error"
	StatusReason      *string            `json:"status_reason,omitempty"`
	Licenses          []LicenseInfo      `json:"licenses"`
	LicenseReferences []LicenseReference `json:"license_references,omitempty"`
}

type LicenseReference struct {
	Path             string   `json:"path"`
	SPDXID           *string  `json:"spdx_id,omitempty"`
	ReferencedNames  []string `json:"referenced_names,omitempty"`
	ReferencePattern *string  `json:"reference_pattern,omitempty"`
}

type LicenseInfo struct {
	Path                 string   `json:"path"`
	SPDXID               *string  `json:"spdx_id,omitempty"`
	Name                 *string  `json:"name,omitempty"`
	Kind                 *string  `json:"kind,omitempty"`
	Similarity           *float64 `json:"similarity,omitempty"`
	Modified             bool     `json:"modified"`
	ExtraCharacters      *string  `json:"extra_characters,omitempty"`
	ExtraCharactersCount *int     `json:"extra_characters_count,omitempty"`
	Restrictions         []string `json:"restrictions,omitempty"`
	Approvers            []string `json:"approvers,omitempty"`
	Error                *string  `json:"error,omitempty"`
	TextURL              *string  `json:"text_url,omitempty"`
}

// VulnerabilityMetadata represents source/vulnerabilities.yml
type VulnerabilityMetadata struct {
	Ecosystem       string              `json:"ecosystem"`
	PackageName     string              `json:"package_name"`
	Status          string              `json:"status"` // "success" | "skipped" | "error"
	CollectedAt     *time.Time          `json:"collected_at,omitempty"`
	StatusReason    *string             `json:"status_reason,omitempty"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
	NVDErrors       []string            `json:"nvd_errors,omitempty"` // CVE IDs that failed NVD enrichment
}

// CVSSAssessment represents a single CVSS assessment from a source
type CVSSAssessment struct {
	Source       string  `json:"source"`        // e.g., "nvd@nist.gov", "report@snyk.io"
	Score        float64 `json:"score"`         // e.g., 9.8
	Severity     string  `json:"severity"`      // e.g., "CRITICAL", "HIGH"
	VectorString string  `json:"vector_string"` // e.g., "CVSS:3.1/AV:N/AC:L/..."
}

// CVSSAssessments contains structured CVSS assessment data
type CVSSAssessments struct {
	Primary   CVSSAssessment   `json:"primary"`             // The selected/primary assessment
	Secondary []CVSSAssessment `json:"secondary,omitempty"` // Alternative assessments
	Version   string           `json:"version"`             // CVSS version (2.0, 3.0, 3.1, 4.0)
}

// AffectedRange preserves OSV's paired [introduced, fixed) interval structure.
type AffectedRange struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed,omitempty"`
	RangeType  string `json:"range_type"`
}

type VulnerabilityInfo struct {
	ID        string    `json:"id"`
	Aliases   []string  `json:"aliases,omitempty"`
	Severity  string    `json:"severity"`
	Published time.Time `json:"published"`
	// FixVersions is a flat bag of fix versions from all sources (OSV, GHSA).
	// Kept separate from AffectedRanges because GHSA only provides a fix version
	// with no introduced version, so it can't form a complete range.
	FixVersions        []string         `json:"fix_versions,omitempty"`
	AffectedVersions   []string         `json:"affected_versions,omitempty"`
	AffectedRanges     []AffectedRange  `json:"affected_ranges,omitempty"`
	Summary            string           `json:"summary"`
	IsMalware          bool             `json:"is_malware,omitempty"`
	ContainsUnknownCWE bool             `json:"contains_unknown_cwe,omitempty"`
	UnknownCWEIDs      []string         `json:"unknown_cwe_ids,omitempty"`
	IsWithdrawn        bool             `json:"is_withdrawn,omitempty"`
	RangeType          *string          `json:"range_type,omitempty"`
	CVSS               *float64         `json:"cvss,omitempty"`
	CVSSVersion        *string          `json:"cvss_version,omitempty"`
	CVSSAssessments    *CVSSAssessments `json:"cvss_assessments,omitempty"`
	PublicReportDate   time.Time        `json:"public_report_date"`
}

func (v *VulnerabilityInfo) HasAnyFixedVersion() bool {
	if len(v.FixVersions) > 0 {
		return true
	}
	for _, r := range v.AffectedRanges {
		if r.Fixed != "" {
			return true
		}
	}
	return false
}

// TimelineMetadata represents packages/{ecosystem}/{name}/timeline.yml
// Contains timeline enrichment data separate from base vulnerability data
type TimelineMetadata struct {
	Ecosystem    string                  `json:"ecosystem"`
	PackageName  string                  `json:"package_name"`
	Status       string                  `json:"status"` // "success" | "skipped" | "error"
	CollectedAt  *time.Time              `json:"collected_at,omitempty"`
	TimelineData map[string]TimelineInfo `json:"timeline_data"` // Key: vulnerability ID
}

// TimelineInfo represents timeline metrics for a single vulnerability
type TimelineInfo struct {
	FirstVersionDate *time.Time `json:"first_version_date,omitempty"`
	PatchDate        *time.Time `json:"patch_date,omitempty"`
	DaysToReport     *int       `json:"days_to_report,omitempty"`
	DaysToPatch      *int       `json:"days_to_patch,omitempty"`
	DaysVulnerable   *int       `json:"days_vulnerable,omitempty"`
	EnrichmentError  *string    `json:"enrichment_error,omitempty"`
}

type ManifestMetadata struct {
	Path     string  `json:"path"`
	Lockfile *string `json:"lockfile,omitempty"`
}

// DependencyMetadata represents source/dependencies.yml
type DependencyMetadata struct {
	Status       string             `json:"status"` // "success" | "skipped" | "error"
	StatusReason *string            `json:"status_reason,omitempty"`
	Manifests    []ManifestMetadata `json:"manifests,omitempty"`
	Direct       []Dependency       `json:"direct"`
	Transitive   []Dependency       `json:"transitive,omitempty"`
	ParseErrors  []ParseError       `json:"parse_errors,omitempty"`
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
