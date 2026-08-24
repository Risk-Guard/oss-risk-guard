// Package sbom provides format-agnostic helpers for reading SBOM files
// produced by the cdx16 and spdx30 sub-packages.
package sbom

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/cdx16"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/spdx23"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/spdx30"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// DirectDep pairs an analysis-identifier key with optional manifest-source
// provenance. Location is nil when the SBOM did not record it.
type DirectDep struct {
	Key      string
	Location *models.LocationInfo
}

// ReadDirectDeps sniffs the SBOM format from the JSON payload and returns the
// deduped, sorted analysis-identifier keys for direct (depth=1) dependencies.
func ReadDirectDeps(raw []byte) ([]string, error) {
	deps, err := ReadDirectDepsWithLocations(raw)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(deps))
	for _, d := range deps {
		out = append(out, d.Key)
	}
	return out, nil
}

// ReadDirectDepsWithLocations is the same as ReadDirectDeps but also returns
// each direct dep's manifest-file provenance when the SBOM carries it.
func ReadDirectDepsWithLocations(raw []byte) ([]DirectDep, error) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		Context     string `json:"@context"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}

	switch {
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-2"):
		ov, err := spdx23.ReadOverview(raw)
		if err != nil {
			return nil, err
		}
		out := make([]DirectDep, 0, len(ov.RootDeps))
		byKey := make(map[string]*models.LocationInfo, len(ov.Packages))
		for _, p := range ov.Packages {
			byKey[p.Key] = p.Location
		}
		for _, key := range ov.RootDeps {
			out = append(out, DirectDep{Key: key, Location: byKey[key]})
		}
		return dedupeAndSort(out), nil
	case probe.BOMFormat == "CycloneDX":
		deps, err := cdx16.ReadDirectDepsWithLocations(raw)
		if err != nil {
			return nil, err
		}
		out := make([]DirectDep, 0, len(deps))
		for _, d := range deps {
			out = append(out, DirectDep{Key: d.Key, Location: d.Location})
		}
		return dedupeAndSort(out), nil
	case probe.Context != "":
		deps, err := spdx30.ReadDirectDepsWithLocations(raw)
		if err != nil {
			return nil, err
		}
		out := make([]DirectDep, 0, len(deps))
		for _, d := range deps {
			out = append(out, DirectDep{Key: d.Key, Location: d.Location})
		}
		return dedupeAndSort(out), nil
	default:
		return nil, fmt.Errorf("unrecognized SBOM format (expected SPDX 3.0 or CycloneDX 1.6)")
	}
}

// Package is one enumerated SBOM package, format-agnostic, for display. The
// ecosystem is recovered from the analysis-identifier key so it matches the
// names used elsewhere in the tool (npm, pypi, rubygems…) rather than a purl
// type (gem, golang…). Deps holds the analysis keys of this package's own
// dependencies, so callers can walk the graph as a tree.
type Package struct {
	Key       string
	Ecosystem string
	Name      string
	Version   string
	PURL      string
	Location  *models.LocationInfo
	Deps      []string
}

// Summary is a format-agnostic, human-readable view of a parsed SBOM: the
// format and spec version, the generating tool, the root component, the root's
// direct dependency keys (RootDeps), and every enumerated package (root
// excluded). RootDeps plus each package's Deps form the dependency graph.
type Summary struct {
	Format      string // "CycloneDX" or "SPDX"
	SpecVersion string
	Tool        string
	RootName    string
	RootDeps    []string
	Packages    []Package
}

// ReadSummary sniffs the SBOM format from the JSON payload and returns a
// format-agnostic Summary: metadata, the dependency graph, and every enumerated
// package (excluding the root), sorted by ecosystem then name then version.
func ReadSummary(raw []byte) (*Summary, error) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		Context     string `json:"@context"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}

	switch {
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-2"):
		ov, err := spdx23.ReadOverview(raw)
		if err != nil {
			return nil, err
		}
		s := &Summary{Format: "SPDX", SpecVersion: ov.SpecVersion, Tool: ov.Tool, RootName: ov.RootName, RootDeps: ov.RootDeps}
		for _, p := range ov.Packages {
			s.Packages = append(s.Packages, toPackage(p.Key, p.Name, p.Version, p.PURL, p.Location, p.Deps))
		}
		sortPackages(s.Packages)
		return s, nil
	case probe.BOMFormat == "CycloneDX":
		ov, err := cdx16.ReadOverview(raw)
		if err != nil {
			return nil, err
		}
		s := &Summary{Format: "CycloneDX", SpecVersion: ov.SpecVersion, Tool: ov.Tool, RootName: ov.RootName, RootDeps: ov.RootDeps}
		for _, p := range ov.Packages {
			s.Packages = append(s.Packages, toPackage(p.Key, p.Name, p.Version, p.PURL, p.Location, p.Deps))
		}
		sortPackages(s.Packages)
		return s, nil
	case probe.Context != "":
		ov, err := spdx30.ReadOverview(raw)
		if err != nil {
			return nil, err
		}
		s := &Summary{Format: "SPDX", SpecVersion: ov.SpecVersion, Tool: ov.Tool, RootName: ov.RootName, RootDeps: ov.RootDeps}
		for _, p := range ov.Packages {
			s.Packages = append(s.Packages, toPackage(p.Key, p.Name, p.Version, p.PURL, p.Location, p.Deps))
		}
		sortPackages(s.Packages)
		return s, nil
	default:
		return nil, fmt.Errorf("unrecognized SBOM format (expected SPDX 3.0 or CycloneDX 1.6)")
	}
}

// toPackage builds a format-agnostic Package, deriving the ecosystem from the
// analysis-identifier key ("package/{eco}/{name}"). Falls back to the purl type
// when the key carries no ecosystem.
func toPackage(key, name, version, purlStr string, loc *models.LocationInfo, deps []string) Package {
	eco := ecosystemFromKey(key)
	if eco == "" {
		eco = ecosystemFromPURL(purlStr)
	}
	return Package{Key: key, Ecosystem: eco, Name: name, Version: version, PURL: purlStr, Location: loc, Deps: deps}
}

// ecosystemFromKey extracts the ecosystem from an analysis-identifier key of
// the form "package/{eco}/{name}". Returns "" for non-package keys (e.g. the
// "source/..." root).
func ecosystemFromKey(key string) string {
	rest, found := strings.CutPrefix(key, "package/")
	if !found {
		return ""
	}
	if i := strings.Index(rest, "/"); i > 0 {
		return rest[:i]
	}
	return ""
}

// ecosystemFromPURL extracts the type from a purl of the form "pkg:{type}/…".
func ecosystemFromPURL(purlStr string) string {
	rest, found := strings.CutPrefix(purlStr, "pkg:")
	if !found {
		return ""
	}
	if i := strings.Index(rest, "/"); i > 0 {
		return rest[:i]
	}
	return ""
}

func sortPackages(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
}

func dedupeAndSort(in []DirectDep) []DirectDep {
	seen := make(map[string]bool, len(in))
	out := make([]DirectDep, 0, len(in))
	for _, d := range in {
		if seen[d.Key] {
			continue
		}
		seen[d.Key] = true
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
