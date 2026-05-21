package models

type DetectedManifest struct {
	Ecosystem      string  `json:"ecosystem"`
	PackageManager *string `json:"package_manager,omitempty"`
	// Multiple paths occur when package managers treat several files as one unit:
	// - Python: pyproject.toml + setup.cfg + setup.py (all define the same package)
	// - Ruby: gemspec + Gemfile (bundler reads both when Gemfile has `gemspec` directive)
	// Parsers must iterate ALL paths, not just Paths[0].
	Paths    []string `json:"paths"`
	Lockfile *string  `json:"lockfile,omitempty"`
}

// DepsTreeEdge represents a dependency relationship from a lockfile.
//
// Key format: "package/{ecosystem}/{name}?version={version}"
// Example: "package/npm/express?version=4.18.2"
type DepsTreeEdge struct {
	// ParentKey: The package that depends on ChildKey.
	//   - Parsers initially set "" for direct dependencies; enrichLockfileEdges
	//     replaces this with the sourceKey (e.g., "source/github.com/foo/bar").
	//   - Full key with version for transitive dependencies.
	ParentKey string `json:"parent"`
	ChildKey  string `json:"child"`
	Ecosystem string `json:"ecosystem"`
	// Dev indicates this package would not exist in a production install.
	// True when the package is only reachable through dev dependency paths from root.
	Dev      bool          `json:"dev,omitempty"`
	Location *LocationInfo `json:"location,omitempty"`
}

type ManifestResult struct {
	DetectedManifest
	Name                 *string             `json:"name,omitempty"`
	Private              bool                `json:"private,omitempty"`
	IsDynamic            bool                `json:"is_dynamic,omitempty"`
	DynamicReason        *string             `json:"dynamic_reason,omitempty"`
	InstallScripts       []string            `json:"install_scripts,omitempty"`
	Dependencies         []Dependency        `json:"dependencies"`
	DynamicDependencies  []DynamicDependency `json:"dynamic_dependencies,omitempty"`
	LockfileDependencies []DepsTreeEdge      `json:"lockfile_dependencies"`
	ParseError           *string             `json:"parse_error,omitempty"`
}

type ManifestsResult struct {
	Manifests   []ManifestResult `json:"manifests"`
	ParseErrors []ParseError     `json:"parse_errors,omitempty"`
}
