package main

import (
	"testing"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"
)

// TestCheckRationaleCoverage guarantees every check that can produce a finding
// has curated "why you should care" wording. whyShouldICare errors on a missing
// entry by design, so without this test a newly added check would only surface
// the gap at a user's `init`. Run here against the real check registry instead.
func TestCheckRationaleCoverage(t *testing.T) {
	metadata, _ := dag_builder.GetAllCheckMetadata(localdag.Builder)

	live := map[string]struct{}{}
	for _, info := range metadata {
		if info.Deprecated {
			continue
		}
		live[info.Code] = struct{}{}
		r, err := whyShouldICare(info.Code)
		if err != nil {
			t.Errorf("check %q has no rationale in checkRationales: %v", info.Code, err)
			continue
		}
		if r.why == "" {
			t.Errorf("check %q has an empty rationale headline", info.Code)
		}
	}

	// Catch stale entries so the map doesn't drift from the registry.
	for code := range checkRationales {
		if _, ok := live[code]; !ok {
			t.Errorf("checkRationales has entry for %q, which is not a live check code", code)
		}
	}
}
