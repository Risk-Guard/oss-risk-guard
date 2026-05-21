package policy_loader

import (
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"
)

type Output struct {
	dag_impl.BaseOutput `json:",inline"`
	Policy              *policy.CompiledPolicy             `json:"policy,omitempty"`
	RawYAML             string                             `json:"raw_yaml,omitempty"`
	Error               string                             `json:"error,omitempty"`
	Overrides           map[string][]policy.PolicyOverride `json:"overrides,omitempty"`
}

func NewOutput(status executiondag.Status, statusReason string, p *policy.CompiledPolicy, rawYAML string, overrides map[string][]policy.PolicyOverride, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(status, statusReason, input),
		Policy:     p,
		RawYAML:    rawYAML,
		Overrides:  overrides,
	}
}

func NewOutputWithError(policyError string, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		Policy:     nil,
		Error:      policyError,
	}
}

func (o *Output) PersistKey() string { return "policy" }
