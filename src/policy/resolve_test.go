package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolve_OverrideSet(t *testing.T) {
	override := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 1,
			},
		},
	}
	repo := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 1,
			},
		},
	}
	policyDefault := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityIgnore},
				Specificity: 1,
			},
		},
	}

	result := Resolve(override, repo, policyDefault)

	require.Equal(t, override, result)
}

func TestResolve_NoOverride_NoRepo_UsesPolicyDefault(t *testing.T) {
	policyDefault := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 1,
			},
		},
	}

	result := Resolve(nil, nil, policyDefault)

	require.Equal(t, policyDefault, result)
}

func TestResolve_NoOverride_NoRepo_NoDefault_UsesGlobalDefault(t *testing.T) {
	result := Resolve(nil, nil, nil)

	require.NotNil(t, result)
	require.True(t, len(result.Rules) > 0)
}

func TestResolve_NoOverride_HasRepo_MergesWithGlobalDefault(t *testing.T) {
	repo := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 1,
			},
		},
	}

	result := Resolve(nil, repo, nil)

	require.NotNil(t, result)
	require.True(t, len(result.Rules) > len(repo.Rules))
	require.True(t, result.Rules[0].IsOverlay)
}

func TestResolve_NoOverride_HasRepo_HasDefault_MergesRepoWithDefault(t *testing.T) {
	repo := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityWarning},
				Specificity: 1,
			},
		},
	}
	policyDefault := &CompiledPolicy{
		Rules: []SeverityRule{
			{
				Path:        SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
				Value:       SeverityValue{Severity: SeverityBlocking},
				Specificity: 1,
			},
		},
	}

	result := Resolve(nil, repo, policyDefault)

	require.Len(t, result.Rules, 2)
	require.True(t, result.Rules[0].IsOverlay)
	require.Equal(t, SeverityWarning, result.Rules[0].Value.Severity)
}
