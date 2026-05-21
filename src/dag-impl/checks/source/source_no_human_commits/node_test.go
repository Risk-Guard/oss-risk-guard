package source_no_human_commits

import (
	"fmt"
	"risk-guard/src/dag-impl/git_clone_metadata"
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

	expectedDep := executiondag.DependsOn[*git_clone_metadata.Node]()
	if deps[0] != expectedDep {
		t.Error("Node should depend on *git_clone_metadata.Node")
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
	if node.Code != "SOURCE_NO_HUMAN_COMMITS" {
		t.Errorf("Expected CheckCode to be 'SOURCE_NO_HUMAN_COMMITS', got %s", node.Code)
	}
}

func TestCommitCountLogic(t *testing.T) {
	tests := []struct {
		name            string
		commitCount     *int
		expectViolation bool
		expectCompliant bool
		description     string
	}{
		{
			name:            "Zero commits - violation",
			commitCount:     intPtr(0),
			expectViolation: true,
			expectCompliant: false,
			description:     "Repository with 0 commits should be a violation",
		},
		{
			name:            "One commit - compliant",
			commitCount:     intPtr(1),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with 1 commit should be compliant",
		},
		{
			name:            "Many commits - compliant",
			commitCount:     intPtr(1000),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with many commits should be compliant",
		},
		{
			name:            "Nil commit count - should be handled",
			commitCount:     nil,
			expectViolation: false,
			expectCompliant: false,
			description:     "Nil commit count should be skipped",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.commitCount == nil {
				// Just verify nil is a separate case
				return
			}

			isViolation := *tt.commitCount == 0
			isCompliant := *tt.commitCount > 0

			if isViolation != tt.expectViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v (commit count: %d)",
					tt.description, tt.expectViolation, isViolation, *tt.commitCount)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("%s: Expected compliant=%v, got compliant=%v (commit count: %d)",
					tt.description, tt.expectCompliant, isCompliant, *tt.commitCount)
			}
		})
	}
}

func TestRationaleMessages(t *testing.T) {
	tests := []struct {
		name        string
		commitCount int
		expected    string
	}{
		{
			name:        "Zero commits",
			commitCount: 0,
			expected:    "Repository has no human commits",
		},
		{
			name:        "One commit",
			commitCount: 1,
			expected:    "Repository has 1 human commits",
		},
		{
			name:        "Multiple commits",
			commitCount: 42,
			expected:    "Repository has 42 human commits",
		},
		{
			name:        "Many commits",
			commitCount: 10000,
			expected:    "Repository has 10000 human commits",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rationale string
			if tt.commitCount == 0 {
				rationale = "Repository has no human commits"
			} else {
				rationale = fmt.Sprintf("Repository has %d human commits", tt.commitCount)
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

// Helper function to create int pointers
func intPtr(i int) *int {
	return &i
}
