package dag_impl

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/models"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// MergeableOutput is an interface that dag-impl outputs can implement
// to provide data that should be merged back into the Input.
type MergeableOutput interface {
	GetInput() *Input
	GetOutput() *Input
}

type Input struct {
	AnalysisIdentifier string  `json:"analysis_identifier"`
	SourceURL          *string `json:"source_url,omitempty"`
	// SourceDirectory scopes git-history analysis to a subpath of SourceURL for
	// monorepo-hosted packages (from npm's repository.directory). Empty means
	// the whole repository is analyzed.
	SourceDirectory *string              `json:"source_directory,omitempty"`
	Commit          *string              `json:"commit,omitempty"`
	Version         *string              `json:"version,omitempty"`
	Packages        []models.PackageInfo `json:"packages,omitempty"`
	Trusted         bool                 `json:"trusted,omitempty"`
	OverridesHash   string               `json:"overrides_hash,omitempty"`

	// Per-run runtime flags. Kept out of JSON so they don't pollute the
	// analysis identity / cache key.
	NoFetch        bool `json:"-"`
	WriteFetchOnly bool `json:"-"`
}

// GetNoFetch satisfies executiondag.NoFetchProvider so the generic executor can
// honor --no-fetch without depending on this package.
func (i Input) GetNoFetch() bool {
	return i.NoFetch
}

// ValidateFetchFlags rejects combinations of --no-fetch and --write-fetch-only
// that don't make sense together.
func ValidateFetchFlags(noFetch, writeFetchOnly bool) error {
	if noFetch && writeFetchOnly {
		return fmt.Errorf("--no-fetch and --write-fetch-only are mutually exclusive")
	}
	return nil
}

func NewPackageInputWithVersion(ecosystem, name string, version *string, overridesHash string) Input {
	analysisID := fmt.Sprintf("package/%s/%s", ecosystem, name)
	if version != nil && *version != "" {
		analysisID += "?version=" + url.QueryEscape(*version)
		if overridesHash != "" {
			analysisID += "&overrides=" + overridesHash
		}
	} else if overridesHash != "" {
		analysisID += "?overrides=" + overridesHash
	}
	var versionStr string
	if version != nil {
		versionStr = *version
	}
	return Input{
		AnalysisIdentifier: analysisID,
		SourceURL:          nil,
		Version:            version,
		Packages: []models.PackageInfo{
			{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   versionStr,
			},
		},
		OverridesHash: overridesHash,
	}
}

// NewSourceInputWithCommit creates a source input with optional commit and trust flag.
// The trusted flag affects AnalysisIdentifier (cache key) because trusted analyses
// apply .riskguardignore patterns which delete files, producing different results.
func NewSourceInputWithCommit(sourceURL string, commit *string, trusted bool) Input {
	return NewSourceInputWithOverrides(sourceURL, commit, trusted, "")
}

func NewSourceInputWithOverrides(sourceURL string, commit *string, trusted bool, overridesHash string) Input {
	// Strip scheme for analysis_identifier (keep full URL for git operations)
	urlForID := sourceURL
	if idx := strings.Index(sourceURL, "://"); idx != -1 {
		urlForID = sourceURL[idx+3:]
	}

	analysisID := fmt.Sprintf("source/%s", urlForID)
	if commit != nil && *commit != "" {
		analysisID = fmt.Sprintf("source/%s?commit=%s", urlForID, *commit)
	}
	if trusted {
		if strings.Contains(analysisID, "?") {
			analysisID += "&trusted=true"
		} else {
			analysisID += "?trusted=true"
		}
	}
	if overridesHash != "" {
		if strings.Contains(analysisID, "?") {
			analysisID += "&overrides=" + overridesHash
		} else {
			analysisID += "?overrides=" + overridesHash
		}
	}
	return Input{
		AnalysisIdentifier: analysisID,
		SourceURL:          &sourceURL,
		Commit:             commit,
		Packages:           nil,
		Trusted:            trusted,
		OverridesHash:      overridesHash,
	}
}

// Merge implements the Mergeable interface.
// This merges node outputs back into the input for downstream nodes.
// Only merges if the node set an Output field (indicating it wants to modify input for downstream).
// - AnalysisIdentifier: Immutable, never merged
// - SourceURL: Can be set from nil/empty, but cannot be changed once set to a non-empty value
// - Packages: Accumulated from all nodes
func (i *Input) Merge(output executiondag.StatusProvider) {
	// Check if output implements MergeableOutput
	mergeableOutput, ok := output.(MergeableOutput)
	if !ok {
		return // Not a mergeable output, nothing to do
	}

	// Get the output field - if nil, node doesn't want to modify input
	outputData := mergeableOutput.GetOutput()
	if outputData == nil {
		return // No output to merge
	}

	// Merge source URL with validation
	if outputData.SourceURL != nil && *outputData.SourceURL != "" {
		// Output has a non-empty URL
		if i.SourceURL == nil || *i.SourceURL == "" {
			// Input URL is nil/empty, safe to set
			i.SourceURL = outputData.SourceURL
		}
		// If URLs differ, keep the existing URL (user-provided takes priority)
		// The PACKAGE_SOURCE_URL_MISMATCH check will detect and report this conflict
		// If URLs are the same, no action needed
	}

	// Merge source directory alongside the URL it scopes. Set-once, like the URL:
	// a value already present (e.g. user-provided) is never overwritten.
	if outputData.SourceDirectory != nil && *outputData.SourceDirectory != "" {
		if i.SourceDirectory == nil || *i.SourceDirectory == "" {
			i.SourceDirectory = outputData.SourceDirectory
		}
	}

	// Merge packages (accumulate with deduplication)
	if len(outputData.Packages) > 0 {
		// Build a set of existing packages for deduplication
		seen := make(map[models.PackageInfo]bool)
		for _, pkg := range i.Packages {
			seen[pkg] = true
		}

		// Only append packages that aren't already present
		for _, pkg := range outputData.Packages {
			if !seen[pkg] {
				i.Packages = append(i.Packages, pkg)
				seen[pkg] = true
			}
		}

		models.SortPackages(i.Packages)
	}
}

// MustHaveSourceURL returns the SourceURL or panics if it's nil/empty.
// This should only be called from nodes that have a hard dependency on
// nodes that provide SourceURL (like git_clone). If this panics, it indicates
// a bug in the DAG framework's dependency resolution.
func (i *Input) MustHaveSourceURL() string {
	if i.SourceURL == nil || *i.SourceURL == "" {
		panic("dag-impl: SourceURL is required but was nil/empty - this indicates a DAG framework bug")
	}
	return *i.SourceURL
}

func (i *Input) HasSourceKey() bool {
	return strings.HasPrefix(i.AnalysisIdentifier, "source/")
}

// BasePath returns a filesystem-safe path derived from AnalysisIdentifier.
// The query-string portion (?version=..., &overrides=..., &trusted=...) is
// preserved as part of the path so distinct work items get distinct dirs;
// otherwise concurrent audits of the same package at different versions race
// on a single destDir and corrupt each other's clones.
func (i *Input) BasePath() string {
	return basePathReplacer.Replace(i.AnalysisIdentifier)
}

var basePathReplacer = strings.NewReplacer("?", "_", "&", "_")

func (i *Input) HasSourceURL() bool {
	return i.SourceURL != nil && *i.SourceURL != ""
}
