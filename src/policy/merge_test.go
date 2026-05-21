package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMerge_NilBase(t *testing.T) {
	overlay := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 1,
			},
		},
	}

	result := merge(nil, overlay)

	require.NotNil(t, result)
	require.Len(t, result.Rules, 1)
	require.Equal(t, SeverityBlocking, result.Rules[0].Value.Severity)
}

func TestMerge_NilOverlay(t *testing.T) {
	base := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 1,
			},
		},
	}

	result := merge(base, nil)

	require.NotNil(t, result)
	require.Len(t, result.Rules, 1)
	require.False(t, result.Rules[0].IsOverlay)
}

func TestMerge_BothNil(t *testing.T) {
	result := merge(nil, nil)
	require.Nil(t, result)
}

func TestMerge_OverlayWinsTiesAtSameSpecificity(t *testing.T) {
	base := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 1,
			},
		},
	}

	overlay := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 1,
			},
		},
	}

	result := merge(base, overlay)

	require.Len(t, result.Rules, 2)
	require.True(t, result.Rules[0].IsOverlay)
	require.Equal(t, SeverityWarning, result.Rules[0].Value.Severity)
	require.False(t, result.Rules[1].IsOverlay)
	require.Equal(t, SeverityBlocking, result.Rules[1].Value.Severity)
}

func TestMerge_HigherSpecificityWins(t *testing.T) {
	base := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: false, Name: "CVE_HIGH"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 2,
			},
		},
	}

	overlay := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 1,
			},
		},
	}

	result := merge(base, overlay)

	require.Len(t, result.Rules, 2)
	require.Equal(t, 2, result.Rules[0].Specificity)
	require.False(t, result.Rules[0].IsOverlay)
	require.Equal(t, 1, result.Rules[1].Specificity)
	require.True(t, result.Rules[1].IsOverlay)
}

func TestMerge_ExpectedFailuresOverlayOverrides(t *testing.T) {
	base := &CompiledPolicy{
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/pkg-a": {Checks: []string{"CHECK_A"}, Reason: "base reason", ApprovedBy: "base-admin"},
			"package/npm/pkg-b": {Checks: []string{"CHECK_B"}, Reason: "only in base"},
		},
	}

	overlay := &CompiledPolicy{
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/pkg-a": {Checks: []string{"CHECK_A"}, Reason: "overlay reason", ApprovedBy: "overlay-admin"},
			"package/npm/pkg-c": {Checks: []string{"CHECK_C"}, Reason: "only in overlay"},
		},
	}

	result := merge(base, overlay)

	require.Len(t, result.ExpectedFailures, 3)
	require.Equal(t, "overlay reason", result.ExpectedFailures["package/npm/pkg-a"].Reason)
	require.Equal(t, "overlay-admin", result.ExpectedFailures["package/npm/pkg-a"].ApprovedBy)
	require.Equal(t, "only in base", result.ExpectedFailures["package/npm/pkg-b"].Reason)
	require.Equal(t, "only in overlay", result.ExpectedFailures["package/npm/pkg-c"].Reason)
}

func TestMerge_WorkflowFromOverlay(t *testing.T) {
	base := &CompiledPolicy{
		Workflow: &WorkflowConfig{Mode: WorkflowModeActive},
	}

	overlay := &CompiledPolicy{
		Workflow: &WorkflowConfig{Mode: WorkflowModeSilent},
	}

	result := merge(base, overlay)

	require.NotNil(t, result.Workflow)
	require.Equal(t, WorkflowModeSilent, result.Workflow.Mode)
}

func TestMerge_WorkflowFallsBackToBase(t *testing.T) {
	base := &CompiledPolicy{
		Workflow: &WorkflowConfig{Mode: WorkflowModeActive},
	}

	overlay := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 1,
			},
		},
	}

	result := merge(base, overlay)

	require.NotNil(t, result.Workflow)
	require.Equal(t, WorkflowModeActive, result.Workflow.Mode)
}

func TestMerge_NoWorkflow(t *testing.T) {
	base := &CompiledPolicy{
		Rules: []SeverityRule{},
	}

	overlay := &CompiledPolicy{
		Rules: []SeverityRule{},
	}

	result := merge(base, overlay)

	require.Nil(t, result.Workflow)
}

func TestMerge_DoesNotMutateInputs(t *testing.T) {
	base := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 1,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/pkg": {Checks: []string{"CHECK"}, Reason: "base"},
		},
	}

	overlay := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "warning"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 1,
			},
		},
		ExpectedFailures: map[string]ExpectedFailureV2{
			"package/npm/pkg2": {Checks: []string{"CHECK"}, Reason: "overlay"},
		},
	}

	result := merge(base, overlay)

	require.Len(t, base.Rules, 1)
	require.Len(t, overlay.Rules, 1)
	require.False(t, base.Rules[0].IsOverlay)
	require.False(t, overlay.Rules[0].IsOverlay)
	require.Len(t, base.ExpectedFailures, 1)
	require.Len(t, overlay.ExpectedFailures, 1)

	require.Len(t, result.Rules, 2)
	require.Len(t, result.ExpectedFailures, 2)
}

func TestMerge_BlockingAfterPreserved(t *testing.T) {
	futureDate := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	base := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityWarning, BlockingAfter: &futureDate},
				Specificity: 1,
			},
		},
	}

	result := merge(base, &CompiledPolicy{})

	require.Len(t, result.Rules, 1)
	require.NotNil(t, result.Rules[0].Value.BlockingAfter)
	require.Equal(t, futureDate, *result.Rules[0].Value.BlockingAfter)
}
