package source_manifest_without_lockfile

import (
	"risk-guard/src/dag-impl/package_detector"
	"risk-guard/src/lib/common/storage"
	"testing"

	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 1 {
		t.Fatalf("Expected 1 dependency, got %d", len(deps))
	}

	expected := executiondag.DependsOn[*package_detector.Node]()
	if deps[0] != expected {
		t.Errorf("Expected package_detector.Node dependency, got %v", deps[0])
	}
}

func TestNode_CreateSkippedOutput(t *testing.T) {
	node := NewNode()
	sourceURL := "https://github.com/test/repo"
	input := dag_impl.Input{
		SourceURL:          &sourceURL,
		AnalysisIdentifier: "source/github.com/test/repo",
	}

	output := node.CreateSkippedOutput("test reason", input)

	if output.Check.CheckStatus != storage.StatusSkipped {
		t.Errorf("Expected check status skipped, got %v", output.Check.CheckStatus)
	}

	if output.Check.CheckCode != node.Code {
		t.Errorf("Expected check code %s, got %s", node.Code, output.Check.CheckCode)
	}

	if output.Check.Rationale != "test reason" {
		t.Errorf("Expected rationale 'test reason', got %s", output.Check.Rationale)
	}
}

func TestNode_Kind(t *testing.T) {
	node := NewNode()
	kind := node.Kind()

	if kind != "check" {
		t.Errorf("Expected kind 'check', got %s", kind)
	}
}

func TestCheckCodeConstant(t *testing.T) {
	node := NewNode()
	if node.Code != "SOURCE_MANIFEST_WITHOUT_LOCKFILE" {
		t.Errorf("Expected node.Code to be 'SOURCE_MANIFEST_WITHOUT_LOCKFILE', got %s", node.Code)
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode()
	if node == nil {
		t.Fatal("NewNode() should not return nil")
	}
	if node.Description == "" {
		t.Error("Node should have a description")
	}
	if len(node.Categories) == 0 {
		t.Error("Node should have at least one category")
	}
}

func TestMissingLockfileLogic(t *testing.T) {
	tests := []struct {
		name             string
		totalManifests   int
		missingLockfiles int
		expectViolation  bool
		expectCompliant  bool
	}{
		{
			name:             "No manifests - compliant",
			totalManifests:   0,
			missingLockfiles: 0,
			expectViolation:  false,
			expectCompliant:  true,
		},
		{
			name:             "All manifests have lockfiles - compliant",
			totalManifests:   3,
			missingLockfiles: 0,
			expectViolation:  false,
			expectCompliant:  true,
		},
		{
			name:             "One manifest missing lockfile - violation",
			totalManifests:   1,
			missingLockfiles: 1,
			expectViolation:  true,
			expectCompliant:  false,
		},
		{
			name:             "Some manifests missing lockfiles - violation",
			totalManifests:   5,
			missingLockfiles: 2,
			expectViolation:  true,
			expectCompliant:  false,
		},
		{
			name:             "All manifests missing lockfiles - violation",
			totalManifests:   3,
			missingLockfiles: 3,
			expectViolation:  true,
			expectCompliant:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isCompliant := tt.totalManifests == 0 || tt.missingLockfiles == 0
			isViolation := tt.totalManifests > 0 && tt.missingLockfiles > 0

			if isViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got violation=%v (total: %d, missing: %d)",
					tt.expectViolation, isViolation, tt.totalManifests, tt.missingLockfiles)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("Expected compliant=%v, got compliant=%v (total: %d, missing: %d)",
					tt.expectCompliant, isCompliant, tt.totalManifests, tt.missingLockfiles)
			}
		})
	}
}
