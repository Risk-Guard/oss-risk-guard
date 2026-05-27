// Package sbom provides format-agnostic helpers for reading SBOM files
// produced by the cdx16 and spdx30 sub-packages.
package sbom

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/cdx16"
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
		BOMFormat string `json:"bomFormat"`
		Context   string `json:"@context"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}

	switch {
	case probe.BOMFormat == "CycloneDX":
		deps, err := cdx16.ReadDirectDepsWithLocations(raw)
		if err != nil {
			return nil, err
		}
		return dedupeAndSort(toDirectDeps(deps)), nil
	case probe.Context != "":
		deps, err := spdx30.ReadDirectDepsWithLocations(raw)
		if err != nil {
			return nil, err
		}
		return dedupeAndSort(toDirectDeps(deps)), nil
	default:
		return nil, fmt.Errorf("unrecognized SBOM format (expected SPDX 3.0 or CycloneDX 1.6)")
	}
}

func toDirectDeps[T interface {
	cdx16.DirectDep | spdx30.DirectDep
}](in []T) []DirectDep {
	out := make([]DirectDep, 0, len(in))
	for _, d := range in {
		switch v := any(d).(type) {
		case cdx16.DirectDep:
			out = append(out, DirectDep{Key: v.Key, Location: v.Location})
		case spdx30.DirectDep:
			out = append(out, DirectDep{Key: v.Key, Location: v.Location})
		}
	}
	return out
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
