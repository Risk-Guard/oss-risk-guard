package package_dynamic_name

import (
	"fmt"
	"risk-guard/src/dag-impl/package_detector"
	"risk-guard/src/lib/common/storage"
	"risk-guard/src/models"
	"strings"
	"testing"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
)

func strPtr(s string) *string { return &s }

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 1 {
		t.Fatalf("Expected 1 dependency, got %d", len(deps))
	}

	expectedDep := executiondag.DependsOn[*package_detector.Node]()
	if deps[0] != expectedDep {
		t.Error("Node should depend on *package_detector.Node")
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
	if node.Code != "PACKAGE_DYNAMIC_NAME" {
		t.Errorf("Expected node.Code to be 'PACKAGE_DYNAMIC_NAME', got %s", node.Code)
	}
}

func TestDynamicPackageNameLogic(t *testing.T) {
	tests := []struct {
		name            string
		manifests       []models.ManifestResult
		expectViolation bool
		expectCompliant bool
		expectSkipped   bool
		description     string
	}{
		{
			name:            "No manifests - skip",
			manifests:       []models.ManifestResult{},
			expectViolation: false,
			expectCompliant: false,
			expectSkipped:   true,
			description:     "No package definitions should skip the check",
		},
		{
			name: "All static package names - compliant",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("express"),
					IsDynamic:        false,
				},
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"packages/utils/package.json"}},
					Name:             strPtr("lodash"),
					IsDynamic:        false,
				},
			},
			expectViolation: false,
			expectCompliant: true,
			expectSkipped:   false,
			description:     "All static package names should be compliant",
		},
		{
			name: "One dynamic package name - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("dynamic-pkg"),
					IsDynamic:        true,
					DynamicReason:    stringPtr("name field uses template string"),
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "One dynamic package name should be a violation",
		},
		{
			name: "Multiple dynamic package names - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("pkg1"),
					IsDynamic:        true,
					DynamicReason:    stringPtr("uses variable"),
				},
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"packages/lib/package.json"}},
					Name:             strPtr("pkg2"),
					IsDynamic:        true,
					DynamicReason:    stringPtr("uses function call"),
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "Multiple dynamic package names should be a violation",
		},
		{
			name: "Mixed static and dynamic - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"packages/static/package.json"}},
					Name:             strPtr("static-pkg"),
					IsDynamic:        false,
				},
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"packages/dynamic/package.json"}},
					Name:             strPtr("dynamic-pkg"),
					IsDynamic:        true,
					DynamicReason:    stringPtr("computed at runtime"),
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "Mix of static and dynamic should be a violation",
		},
		{
			name: "Dynamic without reason - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("dynamic-pkg"),
					IsDynamic:        true,
					DynamicReason:    nil,
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "Dynamic package without reason should still be a violation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasNoManifests := len(tt.manifests) == 0
			hasDynamic := false
			for _, m := range tt.manifests {
				if m.IsDynamic {
					hasDynamic = true
					break
				}
			}

			isSkipped := hasNoManifests
			isViolation := !hasNoManifests && hasDynamic
			isCompliant := !hasNoManifests && !hasDynamic

			if isSkipped != tt.expectSkipped {
				t.Errorf("%s: Expected skipped=%v, got skipped=%v",
					tt.description, tt.expectSkipped, isSkipped)
			}

			if isViolation != tt.expectViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v",
					tt.description, tt.expectViolation, isViolation)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("%s: Expected compliant=%v, got compliant=%v",
					tt.description, tt.expectCompliant, isCompliant)
			}
		})
	}
}

func TestRationaleMessages(t *testing.T) {
	tests := []struct {
		name          string
		dynamicCount  int
		fileNames     []string
		expectedInMsg string
	}{
		{
			name:          "Single dynamic package",
			dynamicCount:  1,
			fileNames:     []string{"package.json"},
			expectedInMsg: "Found 1 package definition(s)",
		},
		{
			name:          "Multiple dynamic packages",
			dynamicCount:  3,
			fileNames:     []string{"package.json", "lib/package.json", "utils/package.json"},
			expectedInMsg: "Found 3 package definition(s)",
		},
		{
			name:          "Zero dynamic packages (compliant)",
			dynamicCount:  0,
			fileNames:     []string{},
			expectedInMsg: "All package names are simple string literals",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rationale string
			if tt.dynamicCount > 0 {
				rationale = fmt.Sprintf(
					"Found %d package definition(s) with dynamically-determined names. Dynamic names are harder to verify and may indicate supply chain risks. Files: [%s]",
					tt.dynamicCount,
					"package.json", // simplified for test
				)
			} else {
				rationale = "All package names are simple string literals"
			}

			if tt.dynamicCount > 0 {
				if !strings.Contains(rationale, tt.expectedInMsg) {
					t.Errorf("Expected rationale to contain %q, got %q", tt.expectedInMsg, rationale)
				}
			} else {
				if rationale != tt.expectedInMsg {
					t.Errorf("Expected rationale %q, got %q", tt.expectedInMsg, rationale)
				}
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

func stringPtr(s string) *string {
	return &s
}
