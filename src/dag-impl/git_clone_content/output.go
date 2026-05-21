package git_clone_content

import (
	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
	"risk-guard/src/models"
)

type Output struct {
	dag_impl.BaseOutput
	RepoPath string `json:"-"`
	Commit   string
}

func NewOutput(status executiondag.Status, statusReason string, repoPath string, commit string, input dag_impl.Input) *Output {
	baseOutput := dag_impl.NewBaseOutput(status, statusReason, input)

	if input.HasSourceURL() {
		baseOutput.Output = &dag_impl.Input{
			SourceURL: input.SourceURL,
			Packages:  []models.PackageInfo{},
		}
	}

	return &Output{
		BaseOutput: baseOutput,
		RepoPath:   repoPath,
		Commit:     commit,
	}
}

func (o *Output) PersistKey() string { return "clone_content" }
