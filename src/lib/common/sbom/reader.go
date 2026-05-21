// Package sbom provides format-agnostic helpers for reading SBOM files
// produced by the cdx16 and spdx30 sub-packages.
package sbom

import (
	"encoding/json"
	"fmt"
	"risk-guard/src/lib/common/sbom/cdx16"
	"risk-guard/src/lib/common/sbom/spdx30"
	"sort"
)

// ReadDirectDeps sniffs the SBOM format from the JSON payload and returns the
// deduped, sorted analysis-identifier keys for direct (depth=1) dependencies.
func ReadDirectDeps(raw []byte) ([]string, error) {
	var probe struct {
		BOMFormat string `json:"bomFormat"`
		Context   string `json:"@context"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}

	var keys []string
	var err error
	switch {
	case probe.BOMFormat == "CycloneDX":
		keys, err = cdx16.ReadDirectDeps(raw)
	case probe.Context != "":
		keys, err = spdx30.ReadDirectDeps(raw)
	default:
		return nil, fmt.Errorf("unrecognized SBOM format (expected SPDX 3.0 or CycloneDX 1.6)")
	}
	if err != nil {
		return nil, err
	}
	return dedupeAndSort(keys), nil
}

func dedupeAndSort(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, k := range in {
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
