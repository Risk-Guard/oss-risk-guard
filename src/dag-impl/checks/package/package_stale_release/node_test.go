package package_stale_release

import (
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/version_transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"testing"
	"time"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 2 {
		t.Fatalf("Expected 2 dependencies, got %d", len(deps))
	}

	expectedTransformerDep := executiondag.DependsOn[*transformer.Node]()
	if deps[0] != expectedTransformerDep {
		t.Error("Node should depend on *transformer.Node")
	}

	expectedVersionDep := executiondag.DependsOn[*version_transformer.Node]()
	if deps[1] != expectedVersionDep {
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

func TestThresholdLogic(t *testing.T) {
	tests := []struct {
		name              string
		daysSinceRelease  int
		expectedViolation bool
		description       string
	}{
		{
			name:              "Recent release - 1 year",
			daysSinceRelease:  365,
			expectedViolation: false,
			description:       "Package released 1 year ago should be compliant",
		},
		{
			name:              "Just under violation threshold - 2.9 years",
			daysSinceRelease:  1058,
			expectedViolation: false,
			description:       "Package released 2.9 years ago should be compliant",
		},
		{
			name:              "At violation threshold - 3 years",
			daysSinceRelease:  3 * 365,
			expectedViolation: true,
			description:       "Package released 3 years ago should be a violation",
		},
		{
			name:              "Between thresholds - 4 years",
			daysSinceRelease:  4 * 365,
			expectedViolation: true,
			description:       "Package released 4 years ago should be a violation",
		},
		{
			name:              "At critical threshold - 5 years",
			daysSinceRelease:  5 * 365,
			expectedViolation: true,
			description:       "Package released 5 years ago should be a violation",
		},
		{
			name:              "Very old release - 10 years",
			daysSinceRelease:  10 * 365,
			expectedViolation: true,
			description:       "Package released 10 years ago should be a violation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yearsSinceRelease := float64(tt.daysSinceRelease) / 365.0

			isViolation := yearsSinceRelease >= float64(violationYears)

			if isViolation != tt.expectedViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v (%.1f years)",
					tt.description, tt.expectedViolation, isViolation, yearsSinceRelease)
			}
		})
	}
}

func TestBuildViolationRationale(t *testing.T) {
	tests := []struct {
		name       string
		violations []string
		expected   string
	}{
		{
			name:       "No violations",
			violations: []string{},
			expected:   "",
		},
		{
			name:       "Single violation",
			violations: []string{"npm/old-package@1.0.0: Package last released 1825 days ago (5.0 years)"},
			expected:   "npm/old-package@1.0.0: Package last released 1825 days ago (5.0 years)",
		},
		{
			name: "Multiple violations",
			violations: []string{
				"npm/old-package-1@1.0.0: Package last released 1825 days ago (5.0 years)",
				"npm/old-package-2@2.0.0: Package last released 1460 days ago (4.0 years)",
			},
			expected: "npm/old-package-1@1.0.0: Package last released 1825 days ago (5.0 years) and 1 other(s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checks.BuildViolationRationale(tt.violations, "", "")
			if result != tt.expected {
				t.Errorf("Expected rationale %q, got %q", tt.expected, result)
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
			compliantPackages: []string{"npm/recent-package@3.0.0: Package was released 365 days ago (1.0 years)"},
			expected:          "npm/recent-package@3.0.0: Package was released 365 days ago (1.0 years)",
		},
		{
			name: "Multiple compliant packages",
			compliantPackages: []string{
				"npm/recent-package-1@3.0.0: Package was released 365 days ago (1.0 years)",
				"npm/recent-package-2@2.1.0: Package was released 730 days ago (2.0 years)",
			},
			expected: "All 2 packages have recent releases",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCompliantRationale(tt.compliantPackages)
			if result != tt.expected {
				t.Errorf("Expected rationale %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCheckCodeConstant(t *testing.T) {
	node := NewNode()
	if node.Code != "PACKAGE_STALE_RELEASE" {
		t.Errorf("Expected CheckCode to be 'PACKAGE_STALE_RELEASE', got %s", node.Code)
	}
}

func TestThresholdConstants(t *testing.T) {
	if violationYears != 3 {
		t.Errorf("Expected violationYears to be 3, got %d", violationYears)
	}
}

func TestYearsCalculation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		releaseDate   time.Time
		expectedYears float64
		tolerance     float64
	}{
		{
			name:          "Exactly 1 year ago",
			releaseDate:   now.AddDate(-1, 0, 0),
			expectedYears: 1.0,
			tolerance:     0.01,
		},
		{
			name:          "Exactly 3 years ago",
			releaseDate:   now.AddDate(-3, 0, 0),
			expectedYears: 3.0,
			tolerance:     0.01,
		},
		{
			name:          "Exactly 5 years ago",
			releaseDate:   now.AddDate(-5, 0, 0),
			expectedYears: 5.0,
			tolerance:     0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daysSince := int(time.Since(tt.releaseDate).Hours() / 24)
			yearsSince := float64(daysSince) / 365.0

			diff := yearsSince - tt.expectedYears
			if diff < 0 {
				diff = -diff
			}

			if diff > tt.tolerance {
				t.Errorf("Expected ~%.1f years, got %.1f years (difference: %.3f)",
					tt.expectedYears, yearsSince, diff)
			}
		})
	}
}
