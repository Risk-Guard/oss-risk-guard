package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadFromBytes_ValidV2(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: blocking
  category/license-compliance: warning
expected_failures:
  package/npm/lodash:
    checks: [VULN_RECENT_FREQUENCY]
    reason: "Known issue"
    approved_by: "admin"
`
	pol, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.NoError(t, err)
	require.NotNil(t, pol)
	require.Len(t, pol.Rules, 2)
	require.Len(t, pol.ExpectedFailures, 1)
	require.Contains(t, pol.ExpectedFailures, "package/npm/lodash")
	require.Equal(t, []string{"VULN_RECENT_FREQUENCY"}, pol.ExpectedFailures["package/npm/lodash"].Checks)
}

func TestLoadFromBytes_InvalidVersion(t *testing.T) {
	yamlData := `
version: 1
severity:
  category/critical: blocking
`
	_, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported version")
}

func TestLoadFromBytes_MissingVersion(t *testing.T) {
	yamlData := `
severity:
  category/critical: blocking
`
	_, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "version field is required")
}

func TestLoadFromBytes_InvalidSeverityPath(t *testing.T) {
	yamlData := `
version: 2
severity:
  invalid/path: blocking
`
	_, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "severity path")
}

func TestLoadFromBytes_InvalidSeverityValue(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: critical
`
	_, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid severity")
}

func TestLoadFromBytes_ExtendedSeverityValue(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical:
    severity: warning
    reason: "Testing purposes"
    blocking_after: "2025-06-01T00:00:00Z"
`
	pol, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.NoError(t, err)
	require.Len(t, pol.Rules, 1)
	require.Equal(t, SeverityWarning, pol.Rules[0].Value.Severity)
	require.Equal(t, "Testing purposes", pol.Rules[0].Value.Reason)
	require.NotNil(t, pol.Rules[0].Value.BlockingAfter)
}

func TestLoadFromBytes_InvalidExpectedFailurePath(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: blocking
expected_failures:
  npm/lodash:
    checks: [CHECK]
    reason: "Bad path - no package/ prefix"
`
	_, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected_failures")
}

func TestLoadFromBytes_MissingChecksArray(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: blocking
expected_failures:
  package/npm/lodash:
    reason: "Missing checks array"
`
	_, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "checks array is required")
}

func TestLoadFromBytes_OldFormatRejected(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: blocking
expected_failures:
  npm/lodash/VULN_CHECK:
    reason: "Old format without package/ prefix"
`
	_, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected_failures")
}

func TestLoadFromBytes_RootExpectedFailure(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: blocking
expected_failures:
  root:
    checks: [SOURCE_NO_LICENSE, SOURCE_FEW_CONTRIBUTORS]
    reason: "Known issue at setup"
    approved_by: "admin@example.com"
`
	pol, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.NoError(t, err)
	require.Len(t, pol.ExpectedFailures, 1)
	require.Contains(t, pol.ExpectedFailures, "root")
	require.Equal(t, []string{"SOURCE_NO_LICENSE", "SOURCE_FEW_CONTRIBUTORS"}, pol.ExpectedFailures["root"].Checks)
	require.Equal(t, "Known issue at setup", pol.ExpectedFailures["root"].Reason)
}

func TestLoadFromBytes_GroupedExpectedFailures(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: blocking
expected_failures:
  package/npm/@alloc/quick-lru:
    checks: [PACKAGE_NAME_MISMATCH, PACKAGE_ACTIVE_MALWARE]
    reason: "Existing issue at setup"
    approved_by: "admin@example.com"
`
	pol, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.NoError(t, err)
	require.Len(t, pol.ExpectedFailures, 1)
	require.Contains(t, pol.ExpectedFailures, "package/npm/@alloc/quick-lru")
	require.Equal(t, []string{"PACKAGE_NAME_MISMATCH", "PACKAGE_ACTIVE_MALWARE"}, pol.ExpectedFailures["package/npm/@alloc/quick-lru"].Checks)
	require.Equal(t, "admin@example.com", pol.ExpectedFailures["package/npm/@alloc/quick-lru"].ApprovedBy)
}

func TestLoadFromBytes_ExpectedWarnings(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: blocking
expected_warnings:
  package/npm/lodash:
    checks: [PACKAGE_STALE_RELEASE]
    reason: "Baselined noise; tracked in #482"
    approved_by: "security@example.com"
  root:
    checks: [SOURCE_FEW_CONTRIBUTORS]
    reason: "Internal repo"
`
	pol, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.NoError(t, err)
	require.Len(t, pol.ExpectedWarnings, 2)
	require.Equal(t, []string{"PACKAGE_STALE_RELEASE"}, pol.ExpectedWarnings["package/npm/lodash"].Checks)
	require.Equal(t, "Baselined noise; tracked in #482", pol.ExpectedWarnings["package/npm/lodash"].Reason)
	require.Empty(t, pol.ExpectedFailures)

	// Round-trips back out so the server and `init` rewrite preserve the section.
	out, err := ToYAML(pol)
	require.NoError(t, err)
	require.Contains(t, out, "expected_warnings")
	require.Contains(t, out, "PACKAGE_STALE_RELEASE")
}

func TestLoadFromBytes_ExpectedWarnings_MissingChecksArray(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: blocking
expected_warnings:
  package/npm/lodash:
    reason: "Missing checks array"
`
	_, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected_warnings")
	require.Contains(t, err.Error(), "checks array is required")
}

func TestLoadFromBytes_SpecificityOrdering(t *testing.T) {
	yamlData := `
version: 2
severity:
  category/critical: blocking
  ecosystem/npm/category/critical: warning
  ecosystem/npm/depth/2+/category/critical: warning
`
	pol, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.NoError(t, err)
	require.Len(t, pol.Rules, 3)

	require.Equal(t, 2, pol.Rules[0].Specificity)
	require.Equal(t, 1, pol.Rules[1].Specificity)
	require.Equal(t, 0, pol.Rules[2].Specificity)
}

func TestLoadFromBytes_WildcardOrdering(t *testing.T) {
	yamlData := `
version: 2
severity:
  check/SOURCE_*: warning
  check/SOURCE_NO_LICENSE: blocking
  check/*: ignore
`
	pol, err := LoadFromBytes([]byte(yamlData), "test.yml")
	require.NoError(t, err)
	require.Len(t, pol.Rules, 3)

	// All have specificity 1 (check, not category)
	// Order by wildcard count ascending: 0, 1, 1
	require.Equal(t, "SOURCE_NO_LICENSE", pol.Rules[0].Path.Target.Name)
	require.Equal(t, 0, pol.Rules[0].WildcardCount)

	require.Equal(t, "SOURCE_*", pol.Rules[1].Path.Target.Name)
	require.Equal(t, 1, pol.Rules[1].WildcardCount)

	require.Equal(t, "*", pol.Rules[2].Path.Target.Name)
	require.Equal(t, 1, pol.Rules[2].WildcardCount)
}

func TestSeverity_Validate(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		wantErr  bool
	}{
		{"empty is invalid", "", true},
		{"blocking is valid", SeverityBlocking, false},
		{"warning is valid", SeverityWarning, false},
		{"ignore is valid", SeverityIgnore, false},
		{"critical is invalid", "critical", true},
		{"typo is invalid", "warnign", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.severity.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDefaultPolicy(t *testing.T) {
	pol := DefaultPolicy()
	require.NotNil(t, pol)
	require.Len(t, pol.Rules, 8)

	criticalFound := false
	for _, rule := range pol.Rules {
		if rule.Path.Target.IsCategory && rule.Path.Target.Name == "critical" && rule.Path.DepthRange == nil {
			require.Equal(t, SeverityBlocking, rule.Value.Severity)
			criticalFound = true
		}
	}
	require.True(t, criticalFound, "critical category rule not found")
}

func TestDefaultPolicy_ReturnsIndependentCopies(t *testing.T) {
	pol1 := DefaultPolicy()
	pol2 := DefaultPolicy()

	require.NotSame(t, pol1, pol2)

	pol1.Rules = append(pol1.Rules, SeverityRule{})
	pol1.ExpectedFailures["test"] = ExpectedFailureV2{Reason: "test"}

	require.Len(t, pol2.Rules, 8)
	require.Len(t, pol2.ExpectedFailures, 0)
}
