package cdx16

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ReadDirectDeps returns the deduped, sorted analysis-identifier keys for the
// SBOM's direct (depth=1) dependencies. The returned keys are decoded from the
// CycloneDX bom-ref encoding produced by Builder (base64 of the original key).
func ReadDirectDeps(raw []byte) ([]string, error) {
	var bom struct {
		Metadata struct {
			Component *struct {
				BOMRef string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
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

	var directRefs []string
	for _, d := range bom.Dependencies {
		if d.Ref == rootRef {
			directRefs = d.DependsOn
			break
		}
	}

	return decodeRefs(directRefs), nil
}

func decodeRefs(refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		decoded, err := base64.RawURLEncoding.DecodeString(r)
		if err != nil {
			continue
		}
		out = append(out, string(decoded))
	}
	return out
}
