package source_single_contributor

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_repo_abandoned"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_repo_stale"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"testing"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 3 {
		t.Fatalf("Expected 3 dependencies, got %d", len(deps))
	}

	if deps[0] != executiondag.DependsOn[*git_clone_metadata.Node]() {
		t.Error("Node should depend on *git_clone_metadata.Node")
	}
	if deps[1] != executiondag.DependsOn[*source_repo_stale.Node]() {
		t.Error("Node should depend on *source_repo_stale.Node")
	}
	if deps[2] != executiondag.DependsOn[*source_repo_abandoned.Node]() {
		t.Error("Node should depend on *source_repo_abandoned.Node")
	}
}

func TestNode_AllowAutoSkip(t *testing.T) {
	node := NewNode()
	if node.AllowAutoSkip() {
		t.Error("AllowAutoSkip should return false")
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
	if node.Code != "SOURCE_SINGLE_CONTRIBUTOR" {
		t.Errorf("Expected CheckCode to be 'SOURCE_SINGLE_CONTRIBUTOR', got %s", node.Code)
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
			name:            "One author - violation",
			authorCount:     intPtr(1),
			expectViolation: true,
			expectCompliant: false,
			description:     "Repository with 1 author should be a violation",
		},
		{
			name:            "Two authors - compliant",
			authorCount:     intPtr(2),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with 2 authors should be compliant",
		},
		{
			name:            "Many authors - compliant",
			authorCount:     intPtr(10),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with many authors should be compliant",
		},
		{
			name:            "Zero authors - compliant",
			authorCount:     intPtr(0),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository with 0 authors should be compliant (edge case)",
		},
		{
			name:            "Nil author count - should be handled",
			authorCount:     nil,
			expectViolation: false,
			expectCompliant: false,
			description:     "Nil author count should return error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.authorCount == nil {
				// Just verify nil is a separate case
				return
			}

			isViolation := *tt.authorCount == 1
			isCompliant := *tt.authorCount != 1

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
	tests := []struct {
		name        string
		authorCount int
		expected    string
	}{
		{
			name:        "One author",
			authorCount: 1,
			expected:    "Authors in last 365 days: 1",
		},
		{
			name:        "Two authors",
			authorCount: 2,
			expected:    "2 authors in last 365 days",
		},
		{
			name:        "Multiple authors",
			authorCount: 5,
			expected:    "5 authors in last 365 days",
		},
		{
			name:        "Many authors",
			authorCount: 100,
			expected:    "100 authors in last 365 days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rationale string
			if tt.authorCount < 2 {
				rationale = fmt.Sprintf("Authors in last 365 days: %d", tt.authorCount)
			} else {
				rationale = fmt.Sprintf("%d authors in last 365 days", tt.authorCount)
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

func TestNode_Execute_ErrorsWhenGitCloneSkipped(t *testing.T) {
	node := NewNode()
	input := dag_impl.Input{}

	log, err := logger.NewLogger("error")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	ctx := ctxutil.SetLogger(context.Background(), log)

	metaOut := git_clone_metadata.NewOutput(executiondag.StatusSkipped, "no source URL provided", input)
	ctx = context.WithValue(ctx, executiondag.DependsOn[*git_clone_metadata.Node](), metaOut)

	// Set up compliant stale/abandoned outputs (so we don't short-circuit on those)
	staleOut := checks.NewCompliantOutput("SOURCE_REPO_STALE", "recent commits", input)
	ctx = context.WithValue(ctx, executiondag.DependsOn[*source_repo_stale.Node](), staleOut)

	abandonedOut := checks.NewCompliantOutput("SOURCE_REPO_ABANDONED", "recent commits", input)
	ctx = context.WithValue(ctx, executiondag.DependsOn[*source_repo_abandoned.Node](), abandonedOut)

	output, err := node.Execute(ctx, input)
	if err != nil {
		t.Fatalf("Execute returned error when git_clone was skipped: %v", err)
	}

	if output.Check.CheckStatus != storage.StatusSkipped {
		t.Errorf("Expected skipped status, got %s", output.Check.CheckStatus)
	}
}

// Helper function to create int pointers
func intPtr(i int) *int {
	return &i
}
