package package_release_cooldown

import (
	"strings"
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/version_transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 1 {
		t.Fatalf("Expected 1 dependency, got %d", len(deps))
	}

	expectedVersionDep := executiondag.DependsOn[*version_transformer.Node]()
	if deps[0] != expectedVersionDep {
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
	}{
		{
			name:              "Just released - 0 days",
			daysSinceRelease:  0,
			expectedViolation: true,
		},
		{
			name:              "3 days ago",
			daysSinceRelease:  3,
			expectedViolation: true,
		},
		{
			name:              "6 days ago",
			daysSinceRelease:  6,
			expectedViolation: true,
		},
		{
			name:              "At threshold - 7 days",
			daysSinceRelease:  7,
			expectedViolation: false,
		},
		{
			name:              "Well past threshold - 30 days",
			daysSinceRelease:  30,
			expectedViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isViolation := tt.daysSinceRelease < defaultCooldownDays

			if isViolation != tt.expectedViolation {
				t.Errorf("Expected violation=%v, got violation=%v (days=%d)",
					tt.expectedViolation, isViolation, tt.daysSinceRelease)
			}
		})
	}
}

func TestCheckCodeConstant(t *testing.T) {
	node := NewNode()
	if node.Code != "PACKAGE_RELEASE_COOLDOWN" {
		t.Errorf("Expected CheckCode to be 'PACKAGE_RELEASE_COOLDOWN', got %s", node.Code)
	}
}

func TestThresholdConstants(t *testing.T) {
	if defaultCooldownDays != 7 {
		t.Errorf("Expected defaultCooldownDays to be 7, got %d", defaultCooldownDays)
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
			compliantPackages: []string{"npm/express@4.19.0: Released 30 days ago"},
			expected:          "npm/express@4.19.0: Released 30 days ago",
		},
		{
			name: "Multiple compliant packages",
			compliantPackages: []string{
				"npm/express@4.19.0: Released 30 days ago",
				"npm/lodash@4.17.21: Released 60 days ago",
			},
			expected: "All 2 packages passed the cooldown period",
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
			violations: []string{"npm/express@4.19.0: Released 2 days ago (2025-02-28)"},
			expected:   "npm/express@4.19.0: Released 2 days ago (2025-02-28)",
		},
		{
			name: "Multiple violations",
			violations: []string{
				"npm/express@4.19.0: Released 2 days ago (2025-02-28)",
				"npm/lodash@4.18.0: Released 1 days ago (2025-03-01)",
			},
			expected: "npm/express@4.19.0: Released 2 days ago (2025-02-28) and 1 other(s)",
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

func TestDaysCalculation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		releaseDate  time.Time
		expectedDays int
		tolerance    int
	}{
		{
			name:         "Released today",
			releaseDate:  now,
			expectedDays: 0,
			tolerance:    0,
		},
		{
			name:         "Released 7 days ago",
			releaseDate:  now.AddDate(0, 0, -7),
			expectedDays: 7,
			tolerance:    0,
		},
		{
			name:         "Released 30 days ago",
			releaseDate:  now.AddDate(0, 0, -30),
			expectedDays: 30,
			tolerance:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daysSince := int(time.Since(tt.releaseDate).Hours() / 24)

			diff := daysSince - tt.expectedDays
			if diff < 0 {
				diff = -diff
			}

			if diff > tt.tolerance {
				t.Errorf("Expected ~%d days, got %d days (difference: %d)",
					tt.expectedDays, daysSince, diff)
			}
		})
	}
}

// A package whose release date the registry does not publish must not be
// silently folded into the compliant count: the cooldown was never measured.
func TestBuildCompliantRationale_UnknownDatesAreCalledOut(t *testing.T) {
	unknown := []string{"maven/com.example:demo@1.0.0: registry publishes no release date"}

	got := buildCompliantRationale([]string{"npm/express@4.19.0: Released 30 days ago"}, unknown)
	want := "npm/express@4.19.0: Released 30 days ago; 1 package(s) had no release date and were not evaluated"
	if got != want {
		t.Errorf("rationale = %q, want %q", got, want)
	}

	got = buildCompliantRationale(nil, unknown)
	if !strings.Contains(got, "not evaluated") {
		t.Errorf("rationale = %q, want it to state the packages were not evaluated", got)
	}
}
