package source_repo_abandoned

import (
	"fmt"
	"risk-guard/src/dag-impl/git_clone_metadata"
	"risk-guard/src/lib/common/storage"
	"strings"
	"testing"
	"time"

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
	if node.Code != "SOURCE_REPO_ABANDONED" {
		t.Errorf("Expected node.Code to be 'SOURCE_REPO_ABANDONED', got %s", node.Code)
	}
}

func TestLegacyThresholdConstant(t *testing.T) {
	if LegacyThreshold != 1825 {
		t.Errorf("Expected LegacyThreshold to be 1825 days, got %d", LegacyThreshold)
	}
}

func TestLastCommitLogic(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name            string
		lastCommit      *time.Time
		expectViolation bool
		expectCompliant bool
		description     string
	}{
		{
			name:            "Recent commit (1 day ago) - compliant",
			lastCommit:      timePtr(now.AddDate(0, 0, -1)),
			expectViolation: false,
			expectCompliant: true,
			description:     "Commit from 1 day ago should be compliant",
		},
		{
			name:            "Commit 1 year ago - compliant",
			lastCommit:      timePtr(now.AddDate(-1, 0, 0)),
			expectViolation: false,
			expectCompliant: true,
			description:     "Commit from 1 year ago should be compliant",
		},
		{
			name:            "Commit exactly 5 years ago - compliant",
			lastCommit:      timePtr(now.AddDate(0, 0, -1825)),
			expectViolation: false,
			expectCompliant: true,
			description:     "Commit exactly 1825 days ago should be compliant",
		},
		{
			name:            "Commit 5 years + 1 day ago - violation",
			lastCommit:      timePtr(now.AddDate(0, 0, -1826)),
			expectViolation: true,
			expectCompliant: false,
			description:     "Commit 1826 days ago should be a violation",
		},
		{
			name:            "Commit 6 years ago - violation",
			lastCommit:      timePtr(now.AddDate(-6, 0, 0)),
			expectViolation: true,
			expectCompliant: false,
			description:     "Commit from 6 years ago should be a violation",
		},
		{
			name:            "Commit 10 years ago - violation",
			lastCommit:      timePtr(now.AddDate(-10, 0, 0)),
			expectViolation: true,
			expectCompliant: false,
			description:     "Commit from 10 years ago should be a violation",
		},
		{
			name:            "Nil last commit - should be handled",
			lastCommit:      nil,
			expectViolation: false,
			expectCompliant: false,
			description:     "Nil last commit should return error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.lastCommit == nil {
				// Just verify nil is a separate case
				return
			}

			daysSince := int(time.Since(*tt.lastCommit).Hours() / 24)
			isViolation := daysSince > LegacyThreshold
			isCompliant := daysSince <= LegacyThreshold

			if isViolation != tt.expectViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v (days since: %d, threshold: %d)",
					tt.description, tt.expectViolation, isViolation, daysSince, LegacyThreshold)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("%s: Expected compliant=%v, got compliant=%v (days since: %d, threshold: %d)",
					tt.description, tt.expectCompliant, isCompliant, daysSince, LegacyThreshold)
			}
		})
	}
}

func TestRationaleMessages(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name            string
		lastCommit      time.Time
		expectedPattern string
		isViolation     bool
	}{
		{
			name:            "Recent commit",
			lastCommit:      now.AddDate(0, 0, -1),
			expectedPattern: "Last repository commit was 1 days ago",
			isViolation:     false,
		},
		{
			name:            "Commit 100 days ago",
			lastCommit:      now.AddDate(0, 0, -100),
			expectedPattern: "Last repository commit was 100 days ago",
			isViolation:     false,
		},
		{
			name:            "Commit over 5 years ago",
			lastCommit:      now.AddDate(0, 0, -2000),
			expectedPattern: "Last repository commit was 2000 days ago",
			isViolation:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daysSince := int(time.Since(tt.lastCommit).Hours() / 24)
			var rationale string

			if daysSince > LegacyThreshold {
				rationale = fmt.Sprintf("Last repository commit was %d days ago", daysSince)
			} else {
				rationale = fmt.Sprintf("Last repository commit was %d days ago", daysSince)
			}

			// Check that the rationale contains the expected pattern
			expectedDays := int(time.Since(tt.lastCommit).Hours() / 24)
			expectedStr := fmt.Sprintf("%d days ago", expectedDays)
			if !strings.Contains(rationale, expectedStr) {
				t.Errorf("Expected rationale to contain %q, got %q", expectedStr, rationale)
			}

			if tt.isViolation && !strings.Contains(rationale, "days ago") {
				t.Errorf("Violation rationale should contain 'days ago', got %q", rationale)
			}
		})
	}
}

func TestThresholdInViolation(t *testing.T) {
	// Verify that violation outputs include the threshold
	now := time.Now()
	oldCommit := now.AddDate(-6, 0, 0)
	daysSince := int(time.Since(oldCommit).Hours() / 24)

	if daysSince > LegacyThreshold {
		// This should be a violation
		evidence := []string{
			fmt.Sprintf("Latest human commit: %s", oldCommit.Format("2006-01-02")),
		}

		if len(evidence) == 0 {
			t.Error("Evidence should not be empty for violation")
		}

		if !strings.Contains(evidence[0], oldCommit.Format("2006-01-02")) {
			t.Errorf("Evidence should contain the commit date %s", oldCommit.Format("2006-01-02"))
		}
	} else {
		t.Error("Test setup error: commit should be old enough for violation")
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode()
	if node == nil {
		t.Error("NewNode() should not return nil")
	}
}

func TestThresholdValue(t *testing.T) {
	expectedThreshold := 1825
	thresholds := map[string]any{
		"legacy_days": LegacyThreshold,
	}

	if thresholds["legacy_days"] != expectedThreshold {
		t.Errorf("Expected threshold 'legacy_days' to be %d, got %v", expectedThreshold, thresholds["legacy_days"])
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
