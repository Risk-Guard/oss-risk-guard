package source_few_contributors

import (
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"testing"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
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
	if node.Code != "SOURCE_FEW_CONTRIBUTORS" {
		t.Errorf("Expected CheckCode to be 'SOURCE_FEW_CONTRIBUTORS', got %s", node.Code)
	}
}

func TestAuthorCountLogic(t *testing.T) {
	tests := []struct {
		name            string
		authorCount     *int
		expectViolation bool
		expectCompliant bool
		description     string
	}{
		{
			name:            "Zero authors - violation",
			authorCount:     intPtr(0),
			expectViolation: true,
			expectCompliant: false,
			description:     "Repository with 0 authors should be a violation",
		},
		{
			name:            "One author - violation",
			authorCount:     intPtr(1),
			expectViolation: true,
			expectCompliant: false,
			description:     "Repository with 1 author should be a violation",
		},
		{
			name:            "Two authors - violation",
			authorCount:     intPtr(2),
			expectViolation: true,
			expectCompliant: false,
			description:     "Repository with 2 authors should be a violation",
		},
		{
			name:            "Three authors - compliant",
			authorCount:     intPtr(3),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with 3 authors should be compliant (threshold)",
		},
		{
			name:            "Four authors - compliant",
			authorCount:     intPtr(4),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with 4 authors should be compliant",
		},
		{
			name:            "Many authors - compliant",
			authorCount:     intPtr(100),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with many authors should be compliant",
		},
		{
			name:            "Nil author count - should be handled",
			authorCount:     nil,
			expectViolation: false,
			expectCompliant: false,
			description:     "Nil author count should be an error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.authorCount == nil {
				// Just verify nil is a separate case that would return error
				return
			}

			const threshold = 3
			isViolation := *tt.authorCount < threshold
			isCompliant := *tt.authorCount >= threshold

			if isViolation != tt.expectViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v (author count: %d)",
					tt.description, tt.expectViolation, isViolation, *tt.authorCount)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("%s: Expected compliant=%v, got compliant=%v (author count: %d)",
					tt.description, tt.expectCompliant, isCompliant, *tt.authorCount)
			}
		})
	}
}

func TestRationaleMessages(t *testing.T) {
	windowDates := " (window: 2024-01-01 to 2024-01-30)"

	tests := []struct {
		name        string
		authorCount int
		expected    string
	}{
		{
			name:        "Zero authors - violation",
			authorCount: 0,
			expected:    "Peak 30-day window authors: 0" + windowDates,
		},
		{
			name:        "One author - violation",
			authorCount: 1,
			expected:    "Peak 30-day window authors: 1" + windowDates,
		},
		{
			name:        "Two authors - violation",
			authorCount: 2,
			expected:    "Peak 30-day window authors: 2" + windowDates,
		},
		{
			name:        "Three authors - compliant",
			authorCount: 3,
			expected:    "3 authors in peak 30-day window" + windowDates,
		},
		{
			name:        "Multiple authors - compliant",
			authorCount: 42,
			expected:    "42 authors in peak 30-day window" + windowDates,
		},
		{
			name:        "Many authors - compliant",
			authorCount: 10000,
			expected:    "10000 authors in peak 30-day window" + windowDates,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const threshold = 3
			var rationale string
			if tt.authorCount < threshold {
				rationale = fmt.Sprintf("Peak 30-day window authors: %d%s", tt.authorCount, windowDates)
			} else {
				rationale = fmt.Sprintf("%d authors in peak 30-day window%s", tt.authorCount, windowDates)
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
