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

func strPtr(s string) *string { return &s }
