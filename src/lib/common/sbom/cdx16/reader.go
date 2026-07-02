package cdx16

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// DirectDep pairs an analysis-identifier key with optional manifest-source
// provenance. Location is nil when the SBOM did not record it.
type DirectDep struct {
	Key      string
	Location *models.LocationInfo
}

// ReadDirectDeps returns the deduped, sorted analysis-identifier keys for the
// SBOM's direct (depth=1) dependencies. The returned keys are decoded from the
// CycloneDX bom-ref encoding produced by Builder (base64 of the original key).
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
	var bom struct {
		Metadata struct {
			Component *struct {
				BOMRef string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BOMRef   string `json:"bom-ref"`
			Evidence *struct {
				Occurrences []Occurrence `json:"occurrences"`
			} `json:"evidence"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, fmt.Errorf("decoding CycloneDX: %w", err)
	}

	if bom.Metadata.Component == nil {
		return nil, fmt.Errorf("CycloneDX missing metadata.component (no root)")
	}
	rootRef := bom.Metadata.Component.BOMRef

	locByRef := make(map[string]*models.LocationInfo)
	for _, c := range bom.Components {
		if c.Evidence == nil || len(c.Evidence.Occurrences) == 0 {
			continue
		}
		occ := c.Evidence.Occurrences[0]
		if occ.Location == "" {
			continue
		}
		loc := &models.LocationInfo{File: strPtr(occ.Location)}
		if occ.Line > 0 {
			ln := occ.Line
			loc.LineNumber = &ln
		}
		locByRef[c.BOMRef] = loc
	}

	var directRefs []string
	for _, d := range bom.Dependencies {
		if d.Ref == rootRef {
			directRefs = d.DependsOn
			break
		}
	}

	out := make([]DirectDep, 0, len(directRefs))
	for _, ref := range directRefs {
		decoded, err := base64.RawURLEncoding.DecodeString(ref)
		if err != nil {
			continue
		}
		out = append(out, DirectDep{Key: string(decoded), Location: locByRef[ref]})
	}
	return out, nil
}

// PackageInfo is one component enumerated from a CycloneDX BOM for display: its
// analysis-identifier key (decoded from the bom-ref), the stored name/version,
// its purl, manifest provenance from Component.Evidence, and the decoded keys
// of its own dependencies (Deps) from the BOM's dependency graph.
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

// ReadOverview parses a CycloneDX 1.6 BOM and returns its metadata, the
// dependency graph, and the full component set minus the root, each with its
// decoded analysis key and manifest provenance. Components whose bom-ref does
// not decode are skipped.
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

	// Decode the dependency edges once: bom-ref -> decoded child keys.
	childKeysByRef := make(map[string][]string, len(bom.Dependencies))
	for _, d := range bom.Dependencies {
		children := make([]string, 0, len(d.DependsOn))
		for _, ref := range d.DependsOn {
			if key, ok := decodeRef(ref); ok {
				children = append(children, key)
			}
		}
		childKeysByRef[d.Ref] = children
	}
	ov.RootDeps = childKeysByRef[rootRef]

	for _, c := range bom.Components {
		if c.BOMRef == rootRef {
			continue
		}
		key, ok := decodeRef(c.BOMRef)
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

// decodeRef decodes a CycloneDX bom-ref (base64 of the analysis key) back to the
// original analysis-identifier key, reporting false when it does not decode.
func decodeRef(ref string) (string, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(ref)
	if err != nil {
		return "", false
	}
	return string(decoded), true
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
