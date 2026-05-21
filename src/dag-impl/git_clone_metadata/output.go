package git_clone_metadata

import (
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

type Output struct {
	dag_impl.BaseOutput
	GitMeta *models.GitMetadata `json:"metadata,omitempty"`
}

func NewOutput(status executiondag.Status, statusReason string, input dag_impl.Input) *Output {
	baseOutput := dag_impl.NewBaseOutput(status, statusReason, input)

	if input.HasSourceURL() {
		baseOutput.Output = &dag_impl.Input{
			SourceURL: input.SourceURL,
		}
	}

	return &Output{
		BaseOutput: baseOutput,
	}
}

func (o *Output) GitMetadata() *models.GitMetadata {
	return o.GitMeta
}

func (o *Output) PersistKey() string { return "clone_metadata" }
