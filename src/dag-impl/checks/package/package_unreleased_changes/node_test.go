package package_unreleased_changes

import (
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/version_transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 3 {
		t.Fatalf("Expected 3 dependencies, got %d", len(deps))
	}

	expectedDep1 := executiondag.DependsOn[*transformer.Node]()
	expectedDep2 := executiondag.DependsOn[*git_clone_metadata.Node]()
	expectedDep3 := executiondag.DependsOn[*version_transformer.Node]()

	foundTransformer := false
	foundGitClone := false
	foundVersionTransformer := false
	for _, dep := range deps {
		if dep == expectedDep1 {
			foundTransformer = true
		}
		if dep == expectedDep2 {
			foundGitClone = true
		}
		if dep == expectedDep3 {
			foundVersionTransformer = true
		}
	}

	if !foundTransformer {
		t.Error("Node should depend on *transformer.Node")
	}
	if !foundGitClone {
		t.Error("Node should depend on *git_clone_metadata.Node")
	}
	if !foundVersionTransformer {
		t.Error("Node should depend on *version_transformer.Node")
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

func TestCheckCodeConstant(t *testing.T) {
	node := NewNode()
	if node.Code != "PACKAGE_UNRELEASED_CHANGES" {
		t.Errorf("Expected CheckCode to be 'PACKAGE_UNRELEASED_CHANGES', got %s", node.Code)
	}
}

func TestOneYearInDaysConstant(t *testing.T) {
	if oneYearInDays != 365 {
		t.Errorf("Expected oneYearInDays to be 365, got %d", oneYearInDays)
	}
}

func TestPackageSkewLogic(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name            string
		releaseDate     time.Time
		latestCommit    time.Time
		expectViolation bool
		expectCompliant bool
		description     string
	}{
		{
			name:            "Recent release, recent commit - compliant",
			releaseDate:     now.AddDate(0, 0, -30), // 30 days ago
			latestCommit:    now.AddDate(0, 0, -20), // 20 days ago
			expectViolation: false,
			expectCompliant: true,
			description:     "Package released 30 days ago, commit 20 days ago should be compliant",
		},
		{
			name:            "Release 400 days ago, recent commit - violation",
			releaseDate:     now.AddDate(0, 0, -400), // 400 days ago
			latestCommit:    now,                     // Today
			expectViolation: true,
			expectCompliant: false,
			description:     "Package released 400 days ago with recent commits should be a violation",
		},
		{
			name:            "Exactly 365 days skew - compliant",
			releaseDate:     now.AddDate(0, 0, -365), // 365 days ago
			latestCommit:    now,                     // Today
			expectViolation: false,
			expectCompliant: true,
			description:     "Exactly 365 days between release and commit should be compliant (threshold is >365)",
		},
		{
			name:            "366 days skew - violation",
			releaseDate:     now.AddDate(0, 0, -366), // 366 days ago
			latestCommit:    now,                     // Today
			expectViolation: true,
			expectCompliant: false,
			description:     "366 days between release and commit should be a violation",
		},
		{
			name:            "Commit before release - compliant",
			releaseDate:     now.AddDate(0, 0, -10), // 10 days ago
			latestCommit:    now.AddDate(0, 0, -20), // 20 days ago (before release)
			expectViolation: false,
			expectCompliant: true,
			description:     "Commit before release (negative skew) should be compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skew := tt.latestCommit.Sub(tt.releaseDate)
			daysAhead := int(skew.Hours() / 24)

			isViolation := daysAhead > oneYearInDays
			isCompliant := !isViolation

			if isViolation != tt.expectViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v (days ahead: %d, threshold: %d)",
					tt.description, tt.expectViolation, isViolation, daysAhead, oneYearInDays)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("%s: Expected compliant=%v, got compliant=%v (days ahead: %d, threshold: %d)",
					tt.description, tt.expectCompliant, isCompliant, daysAhead, oneYearInDays)
			}
		})
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
			compliantPackages: []string{"npm/recent-package@1.0.0: Source is 10 days ahead of last release"},
			expected:          "npm/recent-package@1.0.0: Source is 10 days ahead of last release",
		},
		{
			name: "Multiple compliant packages",
			compliantPackages: []string{
				"npm/recent-package-1@1.0.0: Source is 10 days ahead of last release",
				"npm/recent-package-2@2.0.0: Source is 20 days ahead of last release",
			},
			expected: "All 2 packages are up to date with source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCompliantRationale(tt.compliantPackages, nil)
			if result != tt.expected {
				t.Errorf("Expected rationale %q, got %q", tt.expected, result)
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

func TestThresholdValue(t *testing.T) {
	expectedThreshold := 365
	thresholds := map[string]any{
		"skew_days": oneYearInDays,
	}

	if thresholds["skew_days"] != expectedThreshold {
		t.Errorf("Expected threshold 'skew_days' to be %d, got %v", expectedThreshold, thresholds["skew_days"])
	}
}

func TestSkewCalculation(t *testing.T) {
	// Test various skew scenarios
	now := time.Now()

	tests := []struct {
		name         string
		releaseDate  time.Time
		latestCommit time.Time
		expectedDays int
		description  string
	}{
		{
			name:         "Release 100 days ago, commit today",
			releaseDate:  now.AddDate(0, 0, -100),
			latestCommit: now,
			expectedDays: 100,
			description:  "Should calculate 100 days of skew",
		},
		{
			name:         "Release 400 days ago, commit today",
			releaseDate:  now.AddDate(0, 0, -400),
			latestCommit: now,
			expectedDays: 400,
			description:  "Should calculate 400 days of skew",
		},
		{
			name:         "Release today, commit today",
			releaseDate:  now,
			latestCommit: now,
			expectedDays: 0,
			description:  "Should calculate 0 days of skew when both are today",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skew := tt.latestCommit.Sub(tt.releaseDate)
			daysAhead := int(skew.Hours() / 24)

			// Allow 1 day tolerance for time calculation edge cases
			if daysAhead < tt.expectedDays-1 || daysAhead > tt.expectedDays+1 {
				t.Errorf("%s: Expected ~%d days, got %d days",
					tt.description, tt.expectedDays, daysAhead)
			}
		})
	}
}
