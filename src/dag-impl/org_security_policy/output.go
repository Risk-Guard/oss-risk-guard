package org_security_policy

import (
	"time"

	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
)

type Output struct {
	dag_impl.BaseOutput `json:",inline"`
	Found               bool                           `json:"found"`
	PolicyPath          string                         `json:"policy_path,omitempty"`
	Sources             map[string]executiondag.Source `json:"sources"`
	SourceTimestamp     time.Time                      `json:"source_timestamp"`
}

func NewOutput(status executiondag.Status, statusReason string, found bool, policyPath string, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput:      dag_impl.NewBaseOutput(status, statusReason, input),
		Found:           found,
		PolicyPath:      policyPath,
		Sources:         map[string]executiondag.Source{},
		SourceTimestamp: time.Now(),
	}
}

func (o *Output) WithSources(sources map[string]executiondag.Source) *Output {
	o.Sources = sources
	return o
}

func (o *Output) PersistKey() string { return "org-security-policy" }
