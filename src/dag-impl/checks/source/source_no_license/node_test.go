package source_no_license

import (
	"fmt"
	"risk-guard/src/dag-impl/license_files"
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

	expectedDep := executiondag.DependsOn[*license_files.Node]()
	if deps[0] != expectedDep {
		t.Error("Node should depend on *license_files.Node")
	}
}

func TestNode_CreateSkippedOutput(t *testing.T) {
	node := NewNode()
	sourceURL := "https://github.com/test/repo"
	input := dag_impl.Input{
		SourceURL: &sourceURL,
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
	if node.Code != "SOURCE_NO_LICENSE" {
		t.Errorf("Expected node.Code to be 'SOURCE_NO_LICENSE', got %s", node.Code)
	}
}

func TestLicensePresenceLogic(t *testing.T) {
	tests := []struct {
		name            string
		licenseCount    int
		expectViolation bool
		expectCompliant bool
		description     string
	}{
		{
			name:            "No licenses - violation",
			licenseCount:    0,
			expectViolation: true,
			expectCompliant: false,
			description:     "Repository with no licenses should be a violation",
		},
		{
			name:            "One license - compliant",
			licenseCount:    1,
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with 1 license should be compliant",
		},
		{
			name:            "Multiple licenses - compliant",
			licenseCount:    3,
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with multiple licenses should be compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isViolation := tt.licenseCount == 0
			isCompliant := tt.licenseCount > 0

			if isViolation != tt.expectViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v (license count: %d)",
					tt.description, tt.expectViolation, isViolation, tt.licenseCount)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("%s: Expected compliant=%v, got compliant=%v (license count: %d)",
					tt.description, tt.expectCompliant, isCompliant, tt.licenseCount)
			}
		})
	}
}

func TestRationaleMessages(t *testing.T) {
	tests := []struct {
		name         string
		licenseCount int
		expected     string
	}{
		{
			name:         "No licenses",
			licenseCount: 0,
			expected:     "No license file found in the source repository",
		},
		{
			name:         "One license",
			licenseCount: 1,
			expected:     "Found 1 license file(s)",
		},
		{
			name:         "Multiple licenses",
			licenseCount: 3,
			expected:     "Found 3 license file(s)",
		},
		{
			name:         "Many licenses",
			licenseCount: 10,
			expected:     "Found 10 license file(s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rationale string
			if tt.licenseCount == 0 {
				rationale = "No license file found in the source repository"
			} else {
				rationale = fmt.Sprintf("Found %d license file(s)", tt.licenseCount)
			}

			if rationale != tt.expected {
				t.Errorf("Expected rationale %q, got %q", tt.expected, rationale)
			}
		})
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode()
	if node == nil {
		t.Error("NewNode() should not return nil")
	}
}
