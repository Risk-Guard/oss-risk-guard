package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToPolicy_DuplicatePaths_KeepsHighestPriority(t *testing.T) {
	merged := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 0,
				IsOverlay:   true,
			},
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
				IsOverlay:   false,
			},
		},
	}

	result := ToPolicy(merged)

	require.Equal(t, SeverityWarning, result.Severity["category/critical"].Severity)
}

func TestToYAML_RoundTrip(t *testing.T) {
	original := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: false, Name: "CUSTOM_CHECK"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 1,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/foo": {Checks: []string{"BAR"}, Reason: "test reason"},
		},
	}

	yaml, err := ToYAML(original)
	require.NoError(t, err)
	require.Contains(t, yaml, "category/critical")
	require.Contains(t, yaml, "check/CUSTOM_CHECK")
	require.Contains(t, yaml, "package/npm/foo")
}

func TestSeverityPathToString(t *testing.T) {
	tests := []struct {
		name     string
		path     SeverityPath
		expected string
	}{
		{
			name:     "category only",
			path:     SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
			expected: "category/critical",
		},
		{
			name:     "check only",
			path:     SeverityPath{Target: PathTarget{IsCategory: false, Name: "MALWARE"}},
			expected: "check/MALWARE",
		},
		{
			name: "with ecosystem",
			path: SeverityPath{
				Ecosystem: ptr("npm"),
				Target:    PathTarget{IsCategory: true, Name: "critical"},
			},
			expected: "ecosystem/npm/category/critical",
		},
		{
			name: "with depth exact",
			path: SeverityPath{
				DepthRange: &DepthRange{Min: 1, Max: 1},
				Target:     PathTarget{IsCategory: true, Name: "critical"},
			},
			expected: "depth/1/category/critical",
		},
		{
			name: "with depth range",
			path: SeverityPath{
				DepthRange: &DepthRange{Min: 2, Max: -1},
				Target:     PathTarget{IsCategory: true, Name: "critical"},
			},
			expected: "depth/2+/category/critical",
		},
		{
			name: "with source path",
			path: SeverityPath{
				SourcePath: ptr("github.com/org/repo"),
				Target:     PathTarget{IsCategory: true, Name: "critical"},
			},
			expected: `source/"github.com/org/repo"/category/critical`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := severityPathToString(tt.path)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestSeverityPathToString_Env(t *testing.T) {
	devTrue := true
	devFalse := false
	tests := []struct {
		name     string
		path     SeverityPath
		expected string
	}{
		{
			name:     "env dev + category",
			path:     SeverityPath{Env: &devTrue, Target: PathTarget{IsCategory: true, Name: "critical"}},
			expected: "env/dev/category/critical",
		},
		{
			name:     "env prod + check",
			path:     SeverityPath{Env: &devFalse, Target: PathTarget{IsCategory: false, Name: "VULN"}},
			expected: "env/prod/check/VULN",
		},
		{
			name: "ecosystem + depth + env dev + category",
			path: SeverityPath{
				Ecosystem:  ptr("npm"),
				DepthRange: &DepthRange{Min: 2, Max: -1},
				Env:        &devTrue,
				Target:     PathTarget{IsCategory: true, Name: "critical"},
			},
			expected: "ecosystem/npm/depth/2+/env/dev/category/critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := severityPathToString(tt.path)
			require.Equal(t, tt.expected, result)

			parsed, err := ParseSeverityPath(result)
			require.NoError(t, err)
			require.Equal(t, tt.expected, severityPathToString(*parsed))
		})
	}
}

func ptr(s string) *string {
	return &s
}
