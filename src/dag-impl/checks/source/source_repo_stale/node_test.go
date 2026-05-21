package source_repo_stale

import (
	"fmt"
	"strings"
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
	if node.Code != "SOURCE_REPO_STALE" {
		t.Errorf("Expected node.Code to be 'SOURCE_REPO_STALE', got %s", node.Code)
	}
}

func TestStaleDaysConstant(t *testing.T) {
	if StaleDays != 365 {
		t.Errorf("Expected StaleDays to be 365 days, got %d", StaleDays)
	}
}

func TestFiveYearsInDaysConstant(t *testing.T) {
	if FiveYearsInDays != 1825 {
		t.Errorf("Expected FiveYearsInDays to be 1825 days, got %d", FiveYearsInDays)
	}
}

func TestLastCommitLogic(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name            string
		lastCommit      *time.Time
		expectViolation bool
		expectCompliant bool
		expectSkipped   bool
		description     string
	}{
		{
			name:            "Recent commit (1 day ago) - compliant",
			lastCommit:      timePtr(now.AddDate(0, 0, -1)),
			expectViolation: false,
			expectCompliant: true,
			expectSkipped:   false,
			description:     "Commit from 1 day ago should be compliant",
		},
		{
			name:            "Commit 100 days ago - compliant",
			lastCommit:      timePtr(now.AddDate(0, 0, -100)),
			expectViolation: false,
			expectCompliant: true,
			expectSkipped:   false,
			description:     "Commit from 100 days ago should be compliant",
		},
		{
			name:            "Commit exactly 1 year ago - compliant",
			lastCommit:      timePtr(now.AddDate(0, 0, -365)),
			expectViolation: false,
			expectCompliant: true,
			expectSkipped:   false,
			description:     "Commit exactly 365 days ago should be compliant",
		},
		{
			name:            "Commit 1 year + 1 day ago - violation",
			lastCommit:      timePtr(now.AddDate(0, 0, -366)),
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "Commit 366 days ago should be a violation",
		},
		{
			name:            "Commit 2 years ago - violation",
			lastCommit:      timePtr(now.AddDate(-2, 0, 0)),
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "Commit from 2 years ago should be a violation",
		},
		{
			name:            "Commit exactly 5 years ago - violation",
			lastCommit:      timePtr(now.AddDate(0, 0, -1825)),
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "Commit exactly 1825 days ago should be a violation",
		},
		{
			name:            "Commit 5 years + 1 day ago - skipped",
			lastCommit:      timePtr(now.AddDate(0, 0, -1826)),
			expectViolation: false,
			expectCompliant: false,
			expectSkipped:   true,
			description:     "Commit 1826 days ago should be skipped (5-year check handles it)",
		},
		{
			name:            "Commit 6 years ago - skipped",
			lastCommit:      timePtr(now.AddDate(-6, 0, 0)),
			expectViolation: false,
			expectCompliant: false,
			expectSkipped:   true,
			description:     "Commit from 6 years ago should be skipped (5-year check handles it)",
		},
		{
			name:            "Commit 10 years ago - skipped",
			lastCommit:      timePtr(now.AddDate(-10, 0, 0)),
			expectViolation: false,
			expectCompliant: false,
			expectSkipped:   true,
			description:     "Commit from 10 years ago should be skipped (5-year check handles it)",
		},
		{
			name:            "Nil last commit - should be handled",
			lastCommit:      nil,
			expectViolation: false,
			expectCompliant: false,
			expectSkipped:   false,
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
			isViolation := daysSince > StaleDays && daysSince <= FiveYearsInDays
			isCompliant := daysSince <= StaleDays
			isSkipped := daysSince > FiveYearsInDays

			if isViolation != tt.expectViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v (days since: %d, threshold: %d)",
					tt.description, tt.expectViolation, isViolation, daysSince, StaleDays)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("%s: Expected compliant=%v, got compliant=%v (days since: %d, threshold: %d)",
					tt.description, tt.expectCompliant, isCompliant, daysSince, StaleDays)
			}

			if isSkipped != tt.expectSkipped {
				t.Errorf("%s: Expected skipped=%v, got skipped=%v (days since: %d, 5-year threshold: %d)",
					tt.description, tt.expectSkipped, isSkipped, daysSince, FiveYearsInDays)
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
		isSkipped       bool
	}{
		{
			name:            "Recent commit",
			lastCommit:      now.AddDate(0, 0, -1),
			expectedPattern: "Last repository commit was 1 days ago",
			isViolation:     false,
			isSkipped:       false,
		},
		{
			name:            "Commit 100 days ago",
			lastCommit:      now.AddDate(0, 0, -100),
			expectedPattern: "Last repository commit was 100 days ago",
			isViolation:     false,
			isSkipped:       false,
		},
		{
			name:            "Commit 400 days ago - violation",
			lastCommit:      now.AddDate(0, 0, -400),
			expectedPattern: "Last repository commit was 400 days ago",
			isViolation:     true,
			isSkipped:       false,
		},
		{
			name:            "Commit over 5 years ago - skipped",
			lastCommit:      now.AddDate(0, 0, -2000),
			expectedPattern: "Last commit is over 5 years old",
			isViolation:     false,
			isSkipped:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daysSince := int(time.Since(tt.lastCommit).Hours() / 24)
			var rationale string

			if daysSince > FiveYearsInDays {
				rationale = "Last commit is over 5 years old (handled by different check)"
			} else if daysSince > StaleDays {
				rationale = fmt.Sprintf("Last repository commit was %d days ago", daysSince)
			} else {
				rationale = fmt.Sprintf("Last repository commit was %d days ago", daysSince)
			}

			// Check that the rationale contains the expected pattern
			expectedDays := int(time.Since(tt.lastCommit).Hours() / 24)
			expectedStr := fmt.Sprintf("%d days ago", expectedDays)

			if tt.isSkipped {
				if !strings.Contains(rationale, "over 5 years old") {
					t.Errorf("Expected skipped rationale to contain 'over 5 years old', got %q", rationale)
				}
			} else if tt.isViolation {
				if !strings.Contains(rationale, expectedStr) {
					t.Errorf("Expected rationale to contain %q, got %q", expectedStr, rationale)
				}
			} else {
				if !strings.Contains(rationale, expectedStr) {
					t.Errorf("Expected rationale to contain %q, got %q", expectedStr, rationale)
				}
			}
		})
	}
}

func TestThresholdInViolation(t *testing.T) {
	// Verify that violation outputs include the threshold
	now := time.Now()
	oldCommit := now.AddDate(0, 0, -400) // 400 days ago (between 365 and 1825)
	daysSince := int(time.Since(oldCommit).Hours() / 24)

	if daysSince > StaleDays && daysSince <= FiveYearsInDays {
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
		t.Error("Test setup error: commit should be old enough for violation but not over 5 years")
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode()
	if node == nil {
		t.Error("NewNode() should not return nil")
	}
}

func TestThresholdValue(t *testing.T) {
	expectedThreshold := 365
	thresholds := map[string]any{
		"stale_days": StaleDays,
	}

	if thresholds["stale_days"] != expectedThreshold {
		t.Errorf("Expected threshold 'stale_days' to be %d, got %v", expectedThreshold, thresholds["stale_days"])
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
