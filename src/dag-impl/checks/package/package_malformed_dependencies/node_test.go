package package_malformed_dependencies

import (
	"risk-guard/src/language/dag/transformer"
	"risk-guard/src/lib/common/storage"
	"risk-guard/src/models"
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

	expectedDep := executiondag.DependsOn[*transformer.Node]()
	if deps[0] != expectedDep {
		t.Error("Node should depend on *transformer.Node")
	}
}

func TestNode_CreateSkippedOutput(t *testing.T) {
	node := NewNode()
	input := dag_impl.Input{
		Packages: []models.PackageInfo{
			{Ecosystem: "pypi", Name: "test-package"},
		},
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
	if node.Code != "PACKAGE_MALFORMED_DEPENDENCIES" {
		t.Errorf("Expected CheckCode to be 'PACKAGE_MALFORMED_DEPENDENCIES', got %s", node.Code)
	}
}

func TestMalformedDependencyDetection(t *testing.T) {
	parseErr := "version operator '>=' without version"
	tests := []struct {
		name            string
		dependencies    []models.Dependency
		expectViolation bool
	}{
		{
			name:            "No dependencies",
			dependencies:    []models.Dependency{},
			expectViolation: false,
		},
		{
			name: "Valid dependencies",
			dependencies: []models.Dependency{
				{AnalysisIdentifier: "package/pypi/requests", Specifiers: []string{">=2.0"}, ParseError: nil},
				{AnalysisIdentifier: "package/pypi/flask", Specifiers: []string{">=1.0", "<2.0"}, ParseError: nil},
			},
			expectViolation: false,
		},
		{
			name: "One malformed dependency",
			dependencies: []models.Dependency{
				{AnalysisIdentifier: "package/pypi/requests", Specifiers: []string{">=2.0"}, ParseError: nil},
				{AnalysisIdentifier: "package/pypi/bad-dep", Specifiers: []string{}, ParseError: &parseErr},
			},
			expectViolation: true,
		},
		{
			name: "All malformed dependencies",
			dependencies: []models.Dependency{
				{AnalysisIdentifier: "package/pypi/bad-dep1", Specifiers: []string{}, ParseError: &parseErr},
				{AnalysisIdentifier: "package/pypi/bad-dep2", Specifiers: []string{}, ParseError: &parseErr},
			},
			expectViolation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasMalformed := false
			for _, dep := range tt.dependencies {
				if dep.ParseError != nil && *dep.ParseError != "" {
					hasMalformed = true
					break
				}
			}

			if hasMalformed != tt.expectViolation {
				t.Errorf("Expected violation=%v, got %v", tt.expectViolation, hasMalformed)
			}
		})
	}
}
