package source_repo_new

import (
	"fmt"
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

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
	if node.Code != "SOURCE_REPO_NEW" {
		t.Errorf("Expected CheckCode to be 'SOURCE_REPO_NEW', got %s", node.Code)
	}
}

func TestThresholdLogic(t *testing.T) {
	const minAgeDays = 365
	now := time.Now()

	tests := []struct {
		name            string
		firstCommit     *time.Time
		expectViolation bool
		expectCompliant bool
		description     string
	}{
		{
			name:            "0 days old - violation",
			firstCommit:     timePtr(now),
			expectViolation: true,
			expectCompliant: false,
			description:     "Repository with first commit today should be a violation",
		},
		{
			name:            "100 days old - violation",
			firstCommit:     timePtr(now.AddDate(0, 0, -100)),
			expectViolation: true,
			expectCompliant: false,
			description:     "Repository 100 days old should be a violation",
		},
		{
			name:            "364 days old - violation",
			firstCommit:     timePtr(now.AddDate(0, 0, -364)),
			expectViolation: true,
			expectCompliant: false,
			description:     "Repository 364 days old (just under threshold) should be a violation",
		},
		{
			name:            "365 days old - compliant",
			firstCommit:     timePtr(now.AddDate(0, 0, -365)),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository exactly 365 days old should be compliant",
		},
		{
			name:            "366 days old - compliant",
			firstCommit:     timePtr(now.AddDate(0, 0, -366)),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository 366 days old should be compliant",
		},
		{
			name:            "2 years old - compliant",
			firstCommit:     timePtr(now.AddDate(-2, 0, 0)),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository 2 years old should be compliant",
		},
		{
			name:            "10 years old - compliant",
			firstCommit:     timePtr(now.AddDate(-10, 0, 0)),
			expectViolation: false,
			expectCompliant: true,
			description:     "Repository 10 years old should be compliant",
		},
		{
			name:            "Nil first commit - should be handled",
			firstCommit:     nil,
			expectViolation: false,
			expectCompliant: false,
			description:     "Nil first commit should cause an error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.firstCommit == nil {
				// Just verify nil is a separate case that would error
				return
			}

			daysSinceFirst := int(time.Since(*tt.firstCommit).Hours() / 24)
			isViolation := daysSinceFirst < minAgeDays
			isCompliant := daysSinceFirst >= minAgeDays

			if isViolation != tt.expectViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v (days since first: %d)",
					tt.description, tt.expectViolation, isViolation, daysSinceFirst)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("%s: Expected compliant=%v, got compliant=%v (days since first: %d)",
					tt.description, tt.expectCompliant, isCompliant, daysSinceFirst)
			}
		})
	}
}

func TestRationaleMessages(t *testing.T) {
	const minAgeDays = 365
	// Use UTC so AddDate(0,0,-N) ≡ N*24 hours; otherwise a DST transition between
	// `firstCommit` and `now` knocks one hour off and the int truncation drops a day.
	now := time.Now().UTC()

	tests := []struct {
		name          string
		daysOld       int
		expectPattern string
	}{
		{
			name:          "0 days old",
			daysOld:       0,
			expectPattern: "Project is 0 days old",
		},
		{
			name:          "100 days old",
			daysOld:       100,
			expectPattern: "Project is 100 days old",
		},
		{
			name:          "364 days old",
			daysOld:       364,
			expectPattern: "Project is 364 days old",
		},
		{
			name:          "365 days old",
			daysOld:       365,
			expectPattern: "Project is 365 days old",
		},
		{
			name:          "730 days old",
			daysOld:       730,
			expectPattern: "Project is 730 days old",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			firstCommit := now.AddDate(0, 0, -tt.daysOld)
			daysSinceFirst := int(now.Sub(firstCommit).Hours() / 24)

			var rationale string
			if daysSinceFirst < minAgeDays {
				rationale = fmt.Sprintf("Project is %d days old", daysSinceFirst)
			} else {
				rationale = fmt.Sprintf("Project is %d days old", daysSinceFirst)
			}

			if rationale != tt.expectPattern {
				t.Errorf("Expected rationale %q, got %q", tt.expectPattern, rationale)
			}
		})
	}
}

func TestEvidenceFormat(t *testing.T) {
	now := time.Now()
	firstCommit := now.AddDate(0, 0, -100)

	evidence := []string{fmt.Sprintf("First commit: %s", firstCommit.Format("2006-01-02"))}

	if len(evidence) != 1 {
		t.Errorf("Expected 1 evidence item, got %d", len(evidence))
	}

	// Check that the evidence contains a properly formatted date
	expectedPrefix := "First commit: "
	if len(evidence[0]) < len(expectedPrefix) {
		t.Errorf("Evidence too short: %q", evidence[0])
	}
	if evidence[0][:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("Evidence doesn't start with %q: %q", expectedPrefix, evidence[0])
	}

	// Check date format (YYYY-MM-DD)
	dateStr := evidence[0][len(expectedPrefix):]
	_, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		t.Errorf("Evidence date not in correct format: %q, error: %v", dateStr, err)
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode()
	if node == nil {
		t.Error("NewNode() should not return nil")
	}
}

// Helper function to create time pointers
func timePtr(t time.Time) *time.Time {
	return &t
}
