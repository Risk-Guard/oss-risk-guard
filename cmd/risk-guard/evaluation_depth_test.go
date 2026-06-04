package main

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/violations"
)

// TestDepsWithSourceDepth guards the depth bug: every direct-dependency analysis
// must be marked depth 1 (one ancestor = the source) so depth-scoped policy —
// "root" acknowledgements and depth-ranged severity rules — does not leak from
// the depth-0 source onto its dependencies.
func TestDepsWithSourceDepth(t *testing.T) {
	const sourceID = "source/github.com/acme/app?commit=abc"

	deps := []*violations.AnalysisViolations{
		{AnalysisID: "package/pypi/f-ask"},
		nil, // a failed/absent dep must be skipped, not panic
		{AnalysisID: "package/pypi/requests", DependencyPath: []string{"already", "set"}},
	}

	got := depsWithSourceDepth(sourceID, deps)

	if len(got) != 2 {
		t.Fatalf("expected nil entry to be skipped, got %d analyses", len(got))
	}

	// f-ask had no path → becomes depth 1 with the source as its sole ancestor.
	if len(got[0].DependencyPath) != 1 {
		t.Fatalf("f-ask depth = %d, want 1 (DependencyPath=%v)", len(got[0].DependencyPath), got[0].DependencyPath)
	}
	if got[0].DependencyPath[0] != sourceID {
		t.Errorf("f-ask ancestor = %q, want %q", got[0].DependencyPath[0], sourceID)
	}

	// An analysis that already carries a path is left untouched.
	if len(got[1].DependencyPath) != 2 {
		t.Errorf("existing DependencyPath should be preserved, got %v", got[1].DependencyPath)
	}
}
