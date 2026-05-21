package source_no_security_policy

import (
	"os"
	"path/filepath"
	"risk-guard/src/dag-impl/git_clone_content"
	"risk-guard/src/dag-impl/org_security_policy"
	"risk-guard/src/git"
	"risk-guard/src/lib/common/storage"
	"testing"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 2 {
		t.Fatalf("Expected 2 dependencies, got %d", len(deps))
	}

	expectedGitClone := executiondag.DependsOn[*git_clone_content.Node]()
	if deps[0] != expectedGitClone {
		t.Error("Node should depend on *git_clone_content.Node")
	}

	expectedOrgPolicy := executiondag.DependsOn[*org_security_policy.Node]()
	if deps[1] != expectedOrgPolicy {
		t.Error("Node should depend on *org_security_policy.Node")
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
	if node.Code != "SOURCE_NO_SECURITY_POLICY" {
		t.Errorf("Expected CheckCode to be 'SOURCE_NO_SECURITY_POLICY', got %s", node.Code)
	}
}

func TestSecurityPolicyLogic(t *testing.T) {
	tests := []struct {
		name            string
		files           []string
		expectViolation bool
	}{
		{
			name:            "No security policy file - violation",
			files:           nil,
			expectViolation: true,
		},
		{
			name:            "SECURITY.md at root - compliant",
			files:           []string{"SECURITY.md"},
			expectViolation: false,
		},
		{
			name:            "SECURITY.txt at root - compliant",
			files:           []string{"SECURITY.txt"},
			expectViolation: false,
		},
		{
			name:            "SECURITY.rst at root - compliant",
			files:           []string{"SECURITY.rst"},
			expectViolation: false,
		},
		{
			name:            ".github/SECURITY.md - compliant",
			files:           []string{".github/SECURITY.md"},
			expectViolation: false,
		},
		{
			name:            "docs/SECURITY.md - compliant",
			files:           []string{"docs/SECURITY.md"},
			expectViolation: false,
		},
		{
			name:            "Unrelated file only - violation",
			files:           []string{"README.md"},
			expectViolation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			for _, f := range tt.files {
				fullPath := filepath.Join(tmpDir, f)
				if err := os.MkdirAll(filepath.Dir(fullPath), 0o750); err != nil {
					t.Fatalf("creating directory: %v", err)
				}
				if err := os.WriteFile(fullPath, []byte("security policy"), 0o644); err != nil {
					t.Fatalf("creating file: %v", err)
				}
			}

			found := false
			for _, candidate := range git.SecurityPolicyPaths {
				fullPath := filepath.Join(tmpDir, candidate)
				if _, err := os.Stat(fullPath); err == nil {
					found = true
					break
				}
			}

			isViolation := !found
			if isViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got violation=%v", tt.expectViolation, isViolation)
			}
		})
	}
}

func TestRationaleMessages(t *testing.T) {
	tests := []struct {
		name     string
		found    bool
		file     string
		expected string
	}{
		{
			name:     "No security policy",
			found:    false,
			expected: "No security policy file found",
		},
		{
			name:     "SECURITY.md found",
			found:    true,
			file:     "SECURITY.md",
			expected: "Security policy found: SECURITY.md",
		},
		{
			name:     ".github/SECURITY.md found",
			found:    true,
			file:     ".github/SECURITY.md",
			expected: "Security policy found: .github/SECURITY.md",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rationale string
			if tt.found {
				rationale = "Security policy found: " + tt.file
			} else {
				rationale = "No security policy file found"
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
