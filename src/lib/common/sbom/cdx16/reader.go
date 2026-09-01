package cdx16

import (
	"encoding/json"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/sbomkey"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// DirectDep pairs an analysis-identifier key with optional manifest-source
// provenance. Location is nil when the SBOM did not record it.
type DirectDep struct {
	Key      string
	Location *models.LocationInfo
}

// ReadDirectDeps returns the deduped, sorted analysis-identifier keys for the
// SBOM's direct (depth=1) dependencies.
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
// each direct dep's manifest-file provenance, parsed from Component.Evidence.
// Components without evidence yield a nil Location.
func ReadDirectDepsWithLocations(raw []byte) ([]DirectDep, error) {
	var bom BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, fmt.Errorf("decoding CycloneDX: %w", err)
	}

	if bom.Metadata.Component == nil {
		return nil, fmt.Errorf("CycloneDX missing metadata.component (no root)")
	}
	rootRef := bom.Metadata.Component.BOMRef

	locByRef := make(map[string]*models.LocationInfo)
	purlByRef := make(map[string]string, len(bom.Components))
	for _, c := range bom.Components {
		purlByRef[c.BOMRef] = c.PURL
		if loc := occurrenceLocation(c.Evidence); loc != nil {
			locByRef[c.BOMRef] = loc
		}
	}

	directRefs := rootDirectRefs(rootRef, bom.Components, bom.Dependencies, purlByRef)

	out := make([]DirectDep, 0, len(directRefs))
	for _, ref := range directRefs {
		key, ok := sbomkey.Resolve(ref, purlByRef[ref])
		if !ok {
			continue
		}
		out = append(out, DirectDep{Key: key, Location: locByRef[ref]})
	}
	return out, nil
}

// rootDirectRefs returns the bom-refs to audit as the root's direct
// dependencies, degrading the same way spdx30's rootChildIDs does.
//
// A root dependsOn edge is the statement of intent and wins outright. With
// none, every component stands in, minus any that another component depends on
// — those are transitives the producer did record. Returning nothing would pass
// the audit silently.
func rootDirectRefs(rootRef string, components []Component, deps []Dep, purlByRef map[string]string) []string {
	for _, d := range deps {
		if d.Ref == rootRef && len(d.DependsOn) > 0 {
			return dedupeByKey(d.DependsOn, purlByRef)
		}
	}

	dependedOnKeys := make(map[string]bool)
	for _, d := range deps {
		for _, ref := range d.DependsOn {
			if key, ok := sbomkey.Resolve(ref, purlByRef[ref]); ok {
				dependedOnKeys[key] = true
			}
		}
	}

	var refs []string
	for _, c := range components {
		if c.BOMRef == rootRef {
			continue
		}
		if key, ok := sbomkey.Resolve(c.BOMRef, c.PURL); ok && !dependedOnKeys[key] {
			refs = append(refs, c.BOMRef)
		}
	}
	return dedupeByKey(refs, purlByRef)
}

// dedupeByKey keeps the first bom-ref for each resolved analysis key, dropping
// refs that do not resolve. The same logical package is often enumerated more
// than once under different refs (lockfile plus installed manifest).
func dedupeByKey(refs []string, purlByRef map[string]string) []string {
	seen := make(map[string]bool, len(refs))
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		key, ok := sbomkey.Resolve(ref, purlByRef[ref])
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	return out
}

// PackageInfo is one component enumerated from a CycloneDX BOM for display: its
// analysis-identifier key, the stored name/version, its purl, manifest
// provenance from Component.Evidence, and the keys of its own dependencies
// (Deps) from the BOM's dependency graph.
type PackageInfo struct {
	Key      string
	Name     string
	Version  string
	PURL     string
	Location *models.LocationInfo
	Deps     []string
}

// Overview is a read-only, display-oriented view of a CycloneDX BOM: its spec
// version, generating tool, root component name, the root's direct dependency
// keys (RootDeps), and every enumerated package (the root component is
// excluded). Together RootDeps and each package's Deps form the dependency
// graph needed to render a tree.
type Overview struct {
	SpecVersion string
	Tool        string
	RootName    string
	RootDeps    []string
	Packages    []PackageInfo
}

// ReadOverview parses a CycloneDX BOM and returns its metadata, the dependency
// graph, and the full component set minus the root, each with its resolved
// analysis key and manifest provenance. Components whose identity cannot be
// resolved are skipped.
func ReadOverview(raw []byte) (*Overview, error) {
	var bom BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, fmt.Errorf("decoding CycloneDX: %w", err)
	}

	ov := &Overview{SpecVersion: bom.SpecVersion}
	if bom.Metadata.Tools != nil && len(bom.Metadata.Tools.Components) > 0 {
		ov.Tool = bom.Metadata.Tools.Components[0].Name
	}
	var rootRef string
	if bom.Metadata.Component != nil {
		rootRef = bom.Metadata.Component.BOMRef
		ov.RootName = bom.Metadata.Component.Name
	}

	purlByRef := make(map[string]string, len(bom.Components))
	for _, c := range bom.Components {
		purlByRef[c.BOMRef] = c.PURL
	}

	// Resolve the dependency edges once: bom-ref -> child keys.
	childKeysByRef := make(map[string][]string, len(bom.Dependencies))
	for _, d := range bom.Dependencies {
		children := make([]string, 0, len(d.DependsOn))
		for _, ref := range d.DependsOn {
			if key, ok := sbomkey.Resolve(ref, purlByRef[ref]); ok {
				children = append(children, key)
			}
		}
		childKeysByRef[d.Ref] = children
	}
	for _, ref := range rootDirectRefs(rootRef, bom.Components, bom.Dependencies, purlByRef) {
		if key, ok := sbomkey.Resolve(ref, purlByRef[ref]); ok {
			ov.RootDeps = append(ov.RootDeps, key)
		}
	}

	for _, c := range bom.Components {
		if c.BOMRef == rootRef {
			continue
		}
		key, ok := sbomkey.Resolve(c.BOMRef, c.PURL)
		if !ok {
			continue
		}
		pkg := PackageInfo{
			Key:      key,
			Name:     c.Name,
			Version:  c.Version,
			PURL:     c.PURL,
			Location: occurrenceLocation(c.Evidence),
			Deps:     childKeysByRef[c.BOMRef],
		}
		ov.Packages = append(ov.Packages, pkg)
	}
	return ov, nil
}

// occurrenceLocation extracts the first occurrence's file/line from a
// component's evidence, or nil when the component carries no provenance.
func occurrenceLocation(ev *Evidence) *models.LocationInfo {
	if ev == nil || len(ev.Occurrences) == 0 || ev.Occurrences[0].Location == "" {
		return nil
	}
	occ := ev.Occurrences[0]
	loc := &models.LocationInfo{File: strPtr(occ.Location)}
	if occ.Line > 0 {
		ln := occ.Line
		loc.LineNumber = &ln
	}
	return loc
}

func strPtr(s string) *string { return &s }
