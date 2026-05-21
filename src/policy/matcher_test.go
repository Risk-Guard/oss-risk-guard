package policy

import (
	"risk-guard/src/category"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGetSeverity_MultipleMatchingRules_ReturnsMostSevere(t *testing.T) {
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "security-vulnerability"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 0},
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityBlocking}, Specificity: 0},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Categories:     []category.RiskCategory{"critical", "security-vulnerability"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityBlocking, result.Severity)
	require.Equal(t, "category/critical: blocking (default)", result.MatchedRule)
}

func TestGetSeverity_MultipleMatchingRules_OrderIndependent(t *testing.T) {
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityBlocking}, Specificity: 0},
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "security-vulnerability"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 0},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Categories:     []category.RiskCategory{"critical", "security-vulnerability"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityBlocking, result.Severity)
}

func TestGetSeverity_IgnoreIsLeastSevere(t *testing.T) {
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "low-priority"}}, Value: SeverityValue{Severity: SeverityIgnore}, Specificity: 0},
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "security-vulnerability"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 0},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Categories:     []category.RiskCategory{"low-priority", "security-vulnerability"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityWarning, result.Severity)
}

func TestGetSeverity_HigherSpecificityWins(t *testing.T) {
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityBlocking}, Specificity: 0},
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 1},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Categories:     []category.RiskCategory{"critical"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityWarning, result.Severity)
}

func TestGetSeverity_MatchedRule_Override(t *testing.T) {
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 0, IsOverride: true},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Categories:     []category.RiskCategory{"critical"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, "category/critical: warning (override)", result.MatchedRule)
}

func TestGetSeverity_MatchedRule_MergedOverlay(t *testing.T) {
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 0, IsOverlay: true},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Categories:     []category.RiskCategory{"critical"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, "category/critical: warning (repo)", result.MatchedRule)
}

func TestGetSeverity_MatchedRule_MergedDefault(t *testing.T) {
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityBlocking}, Specificity: 0, IsOverlay: false},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Categories:     []category.RiskCategory{"critical"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, "category/critical: blocking (default)", result.MatchedRule)
}

func TestGetSeverity_EnvDevMatchesDevDep(t *testing.T) {
	devTrue := true
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityBlocking}, Specificity: 0},
			{Path: SeverityPath{Env: &devTrue, Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 1},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Dev:            true,
		Categories:     []category.RiskCategory{"critical"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityWarning, result.Severity)
}

func TestGetSeverity_EnvDevDoesNotMatchProdDep(t *testing.T) {
	devTrue := true
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityBlocking}, Specificity: 0},
			{Path: SeverityPath{Env: &devTrue, Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 1},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Dev:            false,
		Categories:     []category.RiskCategory{"critical"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityBlocking, result.Severity)
}

func TestGetSeverity_EnvProdMatchesProdDep(t *testing.T) {
	devFalse := false
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 0},
			{Path: SeverityPath{Env: &devFalse, Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityBlocking}, Specificity: 1},
		},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Dev:            false,
		Categories:     []category.RiskCategory{"critical"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityBlocking, result.Severity)
}

func TestGetSeverity_NoEnvMatchesBoth(t *testing.T) {
	policy := &CompiledPolicy{
		Rules: []SeverityRule{
			{Path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}}, Value: SeverityValue{Severity: SeverityWarning}, Specificity: 0},
		},
	}

	for _, dev := range []bool{true, false} {
		ctx := EvaluationContext{
			CheckCode:      "TEST_CHECK",
			Dev:            dev,
			Categories:     []category.RiskCategory{"critical"},
			EvaluationTime: time.Now(),
		}
		result, err := policy.getSeverity(ctx)
		require.NoError(t, err)
		require.Equal(t, SeverityWarning, result.Severity, "dev=%v should match rule without env filter", dev)
	}
}

func TestGetSeverity_MatchedRule_EmptyOnFallback(t *testing.T) {
	policy := &CompiledPolicy{
		Rules: []SeverityRule{},
	}
	ctx := EvaluationContext{
		CheckCode:      "TEST_CHECK",
		Categories:     []category.RiskCategory{"critical"},
		EvaluationTime: time.Now(),
	}

	result, err := policy.getSeverity(ctx)
	require.NoError(t, err)
	require.Equal(t, SeverityBlocking, result.Severity)
	require.Empty(t, result.MatchedRule)
}
