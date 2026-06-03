package policy

import (
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	"github.com/stretchr/testify/require"
)

func findingsOfKind(findings []Finding, kind FindingKind) []Finding {
	var result []Finding
	for _, f := range findings {
		if f.Kind == kind {
			result = append(result, f)
		}
	}
	return result
}

func testCategoryMap() CheckCategoryMap {
	return CheckCategoryMap{
		"PACKAGE_ACTIVE_MALWARE":  {category.RiskCategoryCritical},
		"PACKAGE_PAST_MALWARE":    {category.RiskCategoryCritical},
		"LICENSE_NOT_APPROVED":    {category.RiskCategoryLicenseCompliance},
		"SOURCE_REPO_STALE":       {category.RiskCategoryContinuityAssurance},
		"PACKAGE_INSTALL_SCRIPTS": {category.RiskCategoryCritical},
	}
}

func TestEvaluate_NoViolations(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/clean-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/clean-pkg",
				DependencyPath: nil,
				Violations:     []violations.Violation{},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "PASS", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingBlocking))
	require.Equal(t, 1, result.Summary.TotalPackages)
	require.Equal(t, 1, result.Summary.UnblockedPackages)
}

func TestEvaluate_UnexpectedViolation(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/bad-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/bad-pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check", Evidence: []string{"evidence1"}},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "BLOCKED", result.Status)
	blocking := findingsOfKind(result.Findings, FindingBlocking)
	require.Len(t, blocking, 1)
	require.Equal(t, "package/npm/bad-pkg", blocking[0].Package)
	require.Equal(t, "PACKAGE_ACTIVE_MALWARE", blocking[0].Check)
	require.Equal(t, 1, result.Summary.Blocking)
	require.Equal(t, "category/critical: blocking (default)", blocking[0].MatchedRule)
}

func TestEvaluate_AcknowledgedViolation(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/risky-pkg": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "known issue", ApprovedBy: "admin"},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/risky-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/risky-pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "PASS", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingBlocking))
	acked := findingsOfKind(result.Findings, FindingAcknowledged)
	require.Len(t, acked, 1)
	require.Contains(t, acked[0].Note, "known issue")
	require.Equal(t, 1, result.Summary.Acknowledged)
}

func TestEvaluate_ExpiredAcknowledgment(t *testing.T) {
	expired := time.Now().Add(-24 * time.Hour)
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/expired-pkg": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "temporary exception", Expires: &expired},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/expired-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/expired-pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "BLOCKED", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingBlocking))
	expiredFindings := findingsOfKind(result.Findings, FindingExpired)
	require.Len(t, expiredFindings, 1)
	require.Contains(t, expiredFindings[0].Note, "temporary exception")
	require.Equal(t, 1, result.Summary.Expired)
}

func TestEvaluate_UnknownCheckReturnsError(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 0,
			},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "UNKNOWN_CHECK", Rationale: "unknown check"},
				},
			},
		},
	}

	_, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")

	require.Error(t, err)
	require.Contains(t, err.Error(), "UNKNOWN_CHECK")
	require.Contains(t, err.Error(), "no category defined")
}

func TestEvaluate_DependencyPath(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/root",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/root",
				DependencyPath: nil,
				Violations:     []violations.Violation{},
			},
			{
				AnalysisID:     "package/npm/nested-dep",
				DependencyPath: []string{"root", "middle"},
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "nested violation"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "BLOCKED", result.Status)
	blocking := findingsOfKind(result.Findings, FindingBlocking)
	require.Len(t, blocking, 1)
	require.Equal(t, []string{"root", "middle"}, blocking[0].DependencyPath)
}

func TestEvaluate_WarningViolation(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryContinuityAssurance)}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 0,
			},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/warn-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/warn-pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "SOURCE_REPO_STALE", Rationale: "warning check failed"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "WARNING", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingBlocking))
	warnings := findingsOfKind(result.Findings, FindingWarning)
	require.Len(t, warnings, 1)
	require.Equal(t, "package/npm/warn-pkg", warnings[0].Package)
	require.Equal(t, 1, result.Summary.Warning)
	require.Equal(t, "category/continuity-assurance: warning (default)", warnings[0].MatchedRule)
}

func TestEvaluate_BlockingAndWarning(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryContinuityAssurance)}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 0,
			},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/mixed-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/mixed-pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "blocking"},
					{CheckCode: "SOURCE_REPO_STALE", Rationale: "warning"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "BLOCKED", result.Status)
	require.Len(t, findingsOfKind(result.Findings, FindingBlocking), 1)
	require.Len(t, findingsOfKind(result.Findings, FindingWarning), 1)
}

func TestEvaluate_NilPolicy(t *testing.T) {
	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "violation"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(nil, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "BLOCKED", result.Status)
	require.Len(t, findingsOfKind(result.Findings, FindingBlocking), 1)
}

func TestGetSeverity_BlockingAfter(t *testing.T) {
	pastDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	futureDate := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now()

	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: false, Name: "PACKAGE_ACTIVE_MALWARE"}},
				Value:       SeverityValue{Severity: SeverityWarning, BlockingAfter: &pastDate},
				Specificity: 1,
			},
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: false, Name: "PACKAGE_PAST_MALWARE"}},
				Value:       SeverityValue{Severity: SeverityWarning, BlockingAfter: &futureDate},
				Specificity: 1,
			},
		},
	}

	ctx := EvaluationContext{
		CheckCode:      "PACKAGE_ACTIVE_MALWARE",
		EvaluationTime: now,
	}
	result, err := pol.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityBlocking, result.Severity)
	require.Contains(t, result.Note, "bumped from warning to blocking")

	ctx = EvaluationContext{
		CheckCode:      "PACKAGE_PAST_MALWARE",
		EvaluationTime: now,
	}
	result, err = pol.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityWarning, result.Severity)
	require.Contains(t, result.Note, "Will become blocking after")
}

func TestEvaluate_UnknownCheckWithKnownCheckReturnsError(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "blocking violation"},
					{CheckCode: "SOME_UNKNOWN_CHECK", Rationale: "unknown check - no category"},
				},
			},
		},
	}

	_, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")

	require.Error(t, err)
	require.Contains(t, err.Error(), "SOME_UNKNOWN_CHECK")
	require.Contains(t, err.Error(), "no category defined")
}

func TestEvaluate_DepthBasedRule(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{DepthRange: &DepthRange{Min: 2, Max: -1}, Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryLicenseCompliance)}},
				Value:       SeverityValue{Severity: SeverityWarning, Reason: "transitive deps"},
				Specificity: 1,
			},
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryLicenseCompliance)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/root",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/direct-dep",
				DependencyPath: []string{"root"},
				Violations: []violations.Violation{
					{CheckCode: "LICENSE_NOT_APPROVED", Rationale: "direct dep license issue"},
				},
			},
			{
				AnalysisID:     "package/npm/transitive-dep",
				DependencyPath: []string{"root", "middle", "deep"},
				Violations: []violations.Violation{
					{CheckCode: "LICENSE_NOT_APPROVED", Rationale: "transitive dep license issue"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "BLOCKED", result.Status)
	require.Len(t, findingsOfKind(result.Findings, FindingBlocking), 1)
	require.Len(t, findingsOfKind(result.Findings, FindingWarning), 1)

	warnings := findingsOfKind(result.Findings, FindingWarning)
	require.Equal(t, "transitive deps", warnings[0].Note)
}

func TestEvaluate_EcosystemBasedRule(t *testing.T) {
	npm := "npm"
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Ecosystem: &npm, Target: PathTarget{IsCategory: false, Name: "PACKAGE_INSTALL_SCRIPTS"}},
				Value:       SeverityValue{Severity: SeverityWarning, Reason: "npm install scripts"},
				Specificity: 2,
			},
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: false, Name: "PACKAGE_INSTALL_SCRIPTS"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 1,
			},
		},
	}

	npmViolations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_INSTALL_SCRIPTS", Rationale: "has install scripts"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, npmViolations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)
	require.Equal(t, "WARNING", result.Status)
	warnings := findingsOfKind(result.Findings, FindingWarning)
	require.Len(t, warnings, 1)
	require.Equal(t, "npm install scripts", warnings[0].Note)

	pypiViolations := &violations.ViolationsResult{
		RootAnalysis: "package/pypi/pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/pypi/pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_INSTALL_SCRIPTS", Rationale: "has install scripts"},
				},
			},
		},
	}

	result, err = EvaluateCompiled(pol, pypiViolations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)
	require.Equal(t, "BLOCKED", result.Status)
	require.Len(t, findingsOfKind(result.Findings, FindingBlocking), 1)
}

func TestEvaluate_WildcardExpectedFailure(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/*": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "wildcard match"},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/any-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/any-pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)
	require.Equal(t, "PASS", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingBlocking))
	acked := findingsOfKind(result.Findings, FindingAcknowledged)
	require.Len(t, acked, 1)
	require.Contains(t, acked[0].Note, "wildcard match")
}

func TestEvaluate_WildcardCheckCode(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: false, Name: "SOURCE_*"}},
				Value:       SeverityValue{Severity: SeverityWarning, Reason: "source checks as warning"},
				Specificity: 1,
			},
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
	}

	catMap := CheckCategoryMap{
		"SOURCE_NO_LICENSE": {category.RiskCategoryCritical},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "SOURCE_NO_LICENSE", Rationale: "no license"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), catMap, "")
	require.NoError(t, err)
	require.Equal(t, "WARNING", result.Status)
	warnings := findingsOfKind(result.Findings, FindingWarning)
	require.Len(t, warnings, 1)
	require.Equal(t, "source checks as warning", warnings[0].Note)
	require.Equal(t, "check/SOURCE_*: warning (default)", warnings[0].MatchedRule)
}

func TestEvaluate_AcknowledgedViolation_VersionedPackage(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/risky-pkg": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "known issue", ApprovedBy: "admin"},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/risky-pkg?version=1.2.3",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/risky-pkg?version=1.2.3",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "PASS", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingBlocking))
	acked := findingsOfKind(result.Findings, FindingAcknowledged)
	require.Len(t, acked, 1)
	require.Contains(t, acked[0].Note, "known issue")
}

func TestEvaluate_AcknowledgedViolation_ScopedPackage_Versioned(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/@alloc/quick-lru": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "owner mismatch", ApprovedBy: "admin"},
		},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "package/npm/@alloc/quick-lru?version=5.2.0",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/@alloc/quick-lru?version=5.2.0",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "PASS", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingBlocking))
	acked := findingsOfKind(result.Findings, FindingAcknowledged)
	require.Len(t, acked, 1)
	require.Contains(t, acked[0].Note, "owner mismatch")
}

func TestEvaluate_AcknowledgedViolation_VersionSpecificPattern(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/risky-pkg?version=1.2.3": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "version-specific", ApprovedBy: "admin"},
		},
	}

	t.Run("matches exact version", func(t *testing.T) {
		v := &violations.ViolationsResult{
			RootAnalysis: "package/npm/risky-pkg?version=1.2.3",
			Analyses: []violations.AnalysisViolations{
				{
					AnalysisID: "package/npm/risky-pkg?version=1.2.3",
					Violations: []violations.Violation{
						{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
					},
				},
			},
		}
		result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
		require.NoError(t, err)
		require.Equal(t, "PASS", result.Status)
		acked := findingsOfKind(result.Findings, FindingAcknowledged)
		require.Len(t, acked, 1)
	})

	t.Run("does not match different version", func(t *testing.T) {
		v := &violations.ViolationsResult{
			RootAnalysis: "package/npm/risky-pkg?version=2.0.0",
			Analyses: []violations.AnalysisViolations{
				{
					AnalysisID: "package/npm/risky-pkg?version=2.0.0",
					Violations: []violations.Violation{
						{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
					},
				},
			},
		}
		result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
		require.NoError(t, err)
		require.Equal(t, "BLOCKED", result.Status)
	})

	t.Run("does not match unversioned", func(t *testing.T) {
		v := &violations.ViolationsResult{
			RootAnalysis: "package/npm/risky-pkg",
			Analyses: []violations.AnalysisViolations{
				{
					AnalysisID: "package/npm/risky-pkg",
					Violations: []violations.Violation{
						{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
					},
				},
			},
		}
		result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
		require.NoError(t, err)
		require.Equal(t, "BLOCKED", result.Status)
	})
}

func TestEvaluate_ExpectedFailure_PrefersMoreSpecific(t *testing.T) {
	expired := time.Now().Add(-24 * time.Hour)
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/pkg":               {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "all versions"},
			"package/npm/pkg?version=1.0.0": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "version-specific", Expires: &expired},
			"package/npm/*":                 {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "wildcard"},
		},
	}

	t.Run("version-specific wins over versionless and wildcard", func(t *testing.T) {
		v := &violations.ViolationsResult{
			RootAnalysis: "package/npm/pkg?version=1.0.0",
			Analyses: []violations.AnalysisViolations{
				{
					AnalysisID: "package/npm/pkg?version=1.0.0",
					Violations: []violations.Violation{
						{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed"},
					},
				},
			},
		}
		result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
		require.NoError(t, err)
		require.Equal(t, "BLOCKED", result.Status)
		expiredFindings := findingsOfKind(result.Findings, FindingExpired)
		require.Len(t, expiredFindings, 1)
		require.Contains(t, expiredFindings[0].Note, "version-specific")
	})

	t.Run("exact wins over wildcard for different version", func(t *testing.T) {
		v := &violations.ViolationsResult{
			RootAnalysis: "package/npm/pkg?version=2.0.0",
			Analyses: []violations.AnalysisViolations{
				{
					AnalysisID: "package/npm/pkg?version=2.0.0",
					Violations: []violations.Violation{
						{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed"},
					},
				},
			},
		}
		result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
		require.NoError(t, err)
		require.Equal(t, "PASS", result.Status)
		acked := findingsOfKind(result.Findings, FindingAcknowledged)
		require.Len(t, acked, 1)
		require.Contains(t, acked[0].Note, "all versions")
	})

	t.Run("exact wins over wildcard for unversioned", func(t *testing.T) {
		v := &violations.ViolationsResult{
			RootAnalysis: "package/npm/pkg",
			Analyses: []violations.AnalysisViolations{
				{
					AnalysisID: "package/npm/pkg",
					Violations: []violations.Violation{
						{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed"},
					},
				},
			},
		}
		result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
		require.NoError(t, err)
		require.Equal(t, "PASS", result.Status)
		acked := findingsOfKind(result.Findings, FindingAcknowledged)
		require.Len(t, acked, 1)
		require.Contains(t, acked[0].Note, "all versions")
	})
}

func TestEvaluate_SourceExpectedFailure(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"source/github.com/org/*": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "org-wide exception"},
		},
	}

	catMap := CheckCategoryMap{
		"PACKAGE_ACTIVE_MALWARE": {category.RiskCategoryCritical},
	}

	violations := &violations.ViolationsResult{
		RootAnalysis: "source/github.com/org/repo?commit=abc123",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "source/github.com/org/repo?commit=abc123",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, violations, "https://github.com/org/repo", time.Now(), catMap, "")
	require.NoError(t, err)
	require.Equal(t, "PASS", result.Status)
	acked := findingsOfKind(result.Findings, FindingAcknowledged)
	require.Len(t, acked, 1)
	require.Contains(t, acked[0].Note, "org-wide exception")
}

func TestEvaluate_RootExpectedFailure(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"root": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "root-level exception", ApprovedBy: "admin"},
		},
	}

	catMap := CheckCategoryMap{
		"PACKAGE_ACTIVE_MALWARE": {category.RiskCategoryCritical},
	}

	t.Run("matches depth 0", func(t *testing.T) {
		v := &violations.ViolationsResult{
			RootAnalysis: "package/npm/root-pkg",
			Analyses: []violations.AnalysisViolations{
				{
					AnalysisID:     "package/npm/root-pkg",
					DependencyPath: nil,
					Violations: []violations.Violation{
						{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
					},
				},
			},
		}
		result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), catMap, "")
		require.NoError(t, err)
		require.Equal(t, "PASS", result.Status)
		acked := findingsOfKind(result.Findings, FindingAcknowledged)
		require.Len(t, acked, 1)
		require.Contains(t, acked[0].Note, "root-level exception")
	})

	t.Run("does not match depth > 0", func(t *testing.T) {
		v := &violations.ViolationsResult{
			RootAnalysis: "package/npm/root-pkg",
			Analyses: []violations.AnalysisViolations{
				{
					AnalysisID:     "package/npm/nested-dep",
					DependencyPath: []string{"root-pkg"},
					Violations: []violations.Violation{
						{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
					},
				},
			},
		}
		result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), catMap, "")
		require.NoError(t, err)
		require.Equal(t, "BLOCKED", result.Status)
	})
}

func TestEvaluate_ExpectedWarning_Acknowledges(t *testing.T) {
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryContinuityAssurance)}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 0,
			},
		},
		ExpectedWarnings: map[string]ExpectedFailureV2{
			"package/npm/noisy-pkg": {Checks: []string{"SOURCE_REPO_STALE"}, Reason: "known stale; baselined", ApprovedBy: "admin"},
		},
	}

	v := &violations.ViolationsResult{
		RootAnalysis: "package/npm/noisy-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/noisy-pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "SOURCE_REPO_STALE", Rationale: "warning check failed"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "PASS", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingWarning))
	acked := findingsOfKind(result.Findings, FindingAcknowledged)
	require.Len(t, acked, 1)
	require.Contains(t, acked[0].Note, "known stale; baselined")
	require.Equal(t, 1, result.Summary.Acknowledged)
	require.Equal(t, 0, result.Summary.Warning)
}

func TestEvaluate_ExpectedWarning_DoesNotSilenceBlocking(t *testing.T) {
	// The same entity+check is listed in expected_warnings, but the finding
	// resolves to blocking severity. expected_warnings must not touch it.
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryCritical)}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 0,
			},
		},
		ExpectedWarnings: map[string]ExpectedFailureV2{
			"package/npm/risky-pkg": {Checks: []string{"PACKAGE_ACTIVE_MALWARE"}, Reason: "must not silence a blocking finding"},
		},
	}

	v := &violations.ViolationsResult{
		RootAnalysis: "package/npm/risky-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/risky-pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "PACKAGE_ACTIVE_MALWARE", Rationale: "failed check"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	require.Equal(t, "BLOCKED", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingAcknowledged))
	require.Len(t, findingsOfKind(result.Findings, FindingBlocking), 1)
	require.Equal(t, 1, result.Summary.Blocking)
}

func TestEvaluate_ExpiredExpectedWarning_RevertsToWarning(t *testing.T) {
	expired := time.Now().Add(-24 * time.Hour)
	pol := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: string(category.RiskCategoryContinuityAssurance)}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 0,
			},
		},
		ExpectedWarnings: map[string]ExpectedFailureV2{
			"package/npm/noisy-pkg": {Checks: []string{"SOURCE_REPO_STALE"}, Reason: "temporary", Expires: &expired},
		},
	}

	v := &violations.ViolationsResult{
		RootAnalysis: "package/npm/noisy-pkg",
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     "package/npm/noisy-pkg",
				DependencyPath: nil,
				Violations: []violations.Violation{
					{CheckCode: "SOURCE_REPO_STALE", Rationale: "warning check failed"},
				},
			},
		},
	}

	result, err := EvaluateCompiled(pol, v, "https://github.com/test/repo", time.Now(), testCategoryMap(), "")
	require.NoError(t, err)

	// A lapsed warning baseline reverts to a plain warning — it never escalates
	// to blocking the way an expired expected_failure does.
	require.Equal(t, "WARNING", result.Status)
	require.Empty(t, findingsOfKind(result.Findings, FindingExpired))
	require.Empty(t, findingsOfKind(result.Findings, FindingAcknowledged))
	require.Len(t, findingsOfKind(result.Findings, FindingWarning), 1)
	require.Equal(t, 1, result.Summary.Warning)
	require.Equal(t, 0, result.Summary.Expired)
}
