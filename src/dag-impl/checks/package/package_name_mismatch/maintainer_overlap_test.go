package package_name_mismatch

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

func TestComputeMaintainerOverlap(t *testing.T) {
	tests := []struct {
		name            string
		mismatchedPkg   []models.Maintainer
		comparisonPkg   []models.Maintainer
		expectedShared  int
		expectedTotal   int
		expectedPercent int
	}{
		{
			name: "100% overlap - all maintainers shared",
			mismatchedPkg: []models.Maintainer{
				{Name: "alice", Email: "alice@example.com"},
				{Name: "bob", Email: "bob@example.com"},
			},
			comparisonPkg: []models.Maintainer{
				{Name: "alice", Email: "alice@example.com"},
				{Name: "bob", Email: "bob@example.com"},
				{Name: "charlie", Email: "charlie@example.com"},
			},
			expectedShared:  2,
			expectedTotal:   2,
			expectedPercent: 100,
		},
		{
			name: "0% overlap - different maintainers",
			mismatchedPkg: []models.Maintainer{
				{Name: "alice", Email: "alice@example.com"},
			},
			comparisonPkg: []models.Maintainer{
				{Name: "bob", Email: "bob@example.com"},
			},
			expectedShared:  0,
			expectedTotal:   1,
			expectedPercent: 0,
		},
		{
			name: "partial overlap - 33%",
			mismatchedPkg: []models.Maintainer{
				{Name: "alice", Email: "alice@example.com"},
				{Name: "bob", Email: "bob@example.com"},
				{Name: "charlie", Email: "charlie@example.com"},
			},
			comparisonPkg: []models.Maintainer{
				{Name: "alice", Email: "alice@example.com"},
			},
			expectedShared:  1,
			expectedTotal:   3,
			expectedPercent: 33,
		},
		{
			name:          "empty mismatched maintainers",
			mismatchedPkg: []models.Maintainer{},
			comparisonPkg: []models.Maintainer{
				{Name: "alice", Email: "alice@example.com"},
			},
			expectedShared:  0,
			expectedTotal:   0,
			expectedPercent: 0,
		},
		{
			name: "case insensitive email matching",
			mismatchedPkg: []models.Maintainer{
				{Name: "Alice", Email: "ALICE@EXAMPLE.COM"},
			},
			comparisonPkg: []models.Maintainer{
				{Name: "alice", Email: "alice@example.com"},
			},
			expectedShared:  1,
			expectedTotal:   1,
			expectedPercent: 100,
		},
		{
			name: "email with whitespace trimmed",
			mismatchedPkg: []models.Maintainer{
				{Name: "alice", Email: " alice@example.com "},
			},
			comparisonPkg: []models.Maintainer{
				{Name: "alice", Email: "alice@example.com"},
			},
			expectedShared:  1,
			expectedTotal:   1,
			expectedPercent: 100,
		},
		{
			name: "maintainers with empty emails are not matched",
			mismatchedPkg: []models.Maintainer{
				{Name: "alice", Email: ""},
				{Name: "bob", Email: "bob@example.com"},
			},
			comparisonPkg: []models.Maintainer{
				{Name: "alice", Email: ""},
				{Name: "bob", Email: "bob@example.com"},
			},
			expectedShared:  1,
			expectedTotal:   2,
			expectedPercent: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeMaintainerOverlap(tt.mismatchedPkg, tt.comparisonPkg)

			if result.SharedCount != tt.expectedShared {
				t.Errorf("SharedCount: got %d, want %d", result.SharedCount, tt.expectedShared)
			}
			if result.TotalMaintainers != tt.expectedTotal {
				t.Errorf("TotalMaintainers: got %d, want %d", result.TotalMaintainers, tt.expectedTotal)
			}
			if result.OverlapPercent != tt.expectedPercent {
				t.Errorf("OverlapPercent: got %d, want %d", result.OverlapPercent, tt.expectedPercent)
			}
		})
	}
}

func TestFormatMaintainerOverlapEvidence(t *testing.T) {
	tests := []struct {
		name     string
		overlap  MaintainerOverlap
		expected string
	}{
		{
			name: "100% overlap",
			overlap: MaintainerOverlap{
				ComparedTo:       "npm/undici",
				SharedCount:      3,
				TotalMaintainers: 3,
				OverlapPercent:   100,
			},
			expected: "Maintainer overlap with npm/undici: 100% (3/3 shared)",
		},
		{
			name: "0% overlap - shows different maintainers warning",
			overlap: MaintainerOverlap{
				ComparedTo:       "npm/undici",
				SharedCount:      0,
				TotalMaintainers: 3,
				OverlapPercent:   0,
			},
			expected: "Maintainer overlap with npm/undici: 0% (0/3 shared) - DIFFERENT MAINTAINERS",
		},
		{
			name: "partial overlap",
			overlap: MaintainerOverlap{
				ComparedTo:       "pypi/flask",
				SharedCount:      2,
				TotalMaintainers: 5,
				OverlapPercent:   40,
			},
			expected: "Maintainer overlap with pypi/flask: 40% (2/5 shared)",
		},
		{
			name: "no maintainers listed",
			overlap: MaintainerOverlap{
				ComparedTo:       "npm/undici",
				TotalMaintainers: 0,
			},
			expected: "Maintainer overlap with npm/undici: Unknown (no maintainers listed)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatMaintainerOverlapEvidence(tt.overlap)
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}
