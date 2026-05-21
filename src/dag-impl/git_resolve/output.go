package git_resolve

import (
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type GitErrorDetails struct {
	Type      string `json:"type"`
	Message   string `json:"message"`
	GitOutput string `json:"git_output,omitempty"`
}

type Output struct {
	dag_impl.BaseOutput
	Commit          string           `json:"commit,omitempty"`
	NormalizedURL   string           `json:"normalized_url,omitempty"`
	IsPrivate       bool             `json:"is_private,omitempty"`
	UnsupportedVCS  bool             `json:"unsupported_vcs,omitempty"`
	GitErrorDetails *GitErrorDetails `json:"git_error_details,omitempty"`
}

func NewOutput(status executiondag.Status, statusReason string, input dag_impl.Input) *Output {
	return NewOutputWithError(status, statusReason, nil, input)
}

func NewOutputWithError(status executiondag.Status, statusReason string, gitErr *GitErrorDetails, input dag_impl.Input) *Output {
	baseOutput := dag_impl.NewBaseOutput(status, statusReason, input)

	if input.HasSourceURL() {
		baseOutput.Output = &dag_impl.Input{
			SourceURL: input.SourceURL,
		}
	}

	return &Output{
		BaseOutput:      baseOutput,
		GitErrorDetails: gitErr,
	}
}

func (o *Output) PersistKey() string { return "git_resolve" }
