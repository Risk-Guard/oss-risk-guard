package package_no_license

import (
	"risk-guard/src/dag-impl/checks"
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
			{Ecosystem: "npm", Name: "test-package"},
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

func TestBuildCompliantRationale(t *testing.T) {
	tests := []struct {
		name              string
		compliantPackages []string
		expected          string
	}{
		{
			name:              "No packages",
			compliantPackages: []string{},
			expected:          "No packages checked",
		},
		{
			name:              "Single compliant package",
			compliantPackages: []string{"npm/licensed-package: Package declares a license"},
			expected:          "npm/licensed-package: Package declares a license",
		},
		{
			name: "Multiple compliant packages",
			compliantPackages: []string{
				"npm/licensed-package-1: Package declares a license",
				"npm/licensed-package-2: Package declares a license",
			},
			expected: "All 2 packages declare licenses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checks.BuildCompliantRationale(tt.compliantPackages, "No packages checked", "packages declare licenses")
			if result != tt.expected {
				t.Errorf("Expected rationale %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCheckCodeConstant(t *testing.T) {
	node := NewNode()
	if node.Code != "PACKAGE_NO_LICENSE" {
		t.Errorf("Expected CheckCode to be 'PACKAGE_NO_LICENSE', got %s", node.Code)
	}
}

func TestHasLicenseLogic(t *testing.T) {
	tests := []struct {
		name           string
		license        *string
		expectedHasLic bool
		description    string
	}{
		{
			name:           "Package with license",
			license:        stringPtr("MIT"),
			expectedHasLic: true,
			description:    "Package with MIT license should pass HasLicense()",
		},
		{
			name:           "Package with empty license",
			license:        stringPtr(""),
			expectedHasLic: false,
			description:    "Package with empty license string should fail HasLicense()",
		},
		{
			name:           "Package with nil license",
			license:        nil,
			expectedHasLic: false,
			description:    "Package with nil license should fail HasLicense()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgMeta := &models.PackageMetadata{
				License: tt.license,
			}

			hasLic := pkgMeta.HasLicense()

			if hasLic != tt.expectedHasLic {
				t.Errorf("%s: Expected HasLicense()=%v, got HasLicense()=%v",
					tt.description, tt.expectedHasLic, hasLic)
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
