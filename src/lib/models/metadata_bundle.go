package models

// MetadataBundle contains all metadata needed for scoring.
// It can represent either:
// - A single package
// - A source repository with multiple packages
type MetadataBundle struct {
	// Identification
	Ecosystem string
	Name      string // package name OR source URL

	// Source metadata (shared across packages, may be nil)
	Git          *GitMetadata
	Licenses     *LicenseMetadata
	Dependencies map[string]*DependencyMetadata // keyed by ecosystem

	// Package-specific metadata (one or more packages)
	Packages []PackageData
}

// PackageData contains metadata for a single package within a bundle
type PackageData struct {
	Ecosystem       string
	Name            string
	Package         *PackageMetadata
	Vulnerabilities *VulnerabilityMetadata // Pre-merged from package + source
}
