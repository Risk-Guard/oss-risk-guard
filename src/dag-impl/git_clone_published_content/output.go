package git_clone_published_content

import (
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// Output carries the on-disk path to the source tree checked out at the
// published version's gitHead commit. It deliberately leaves BaseOutput.Output
// nil: this node produces a side artifact (a working tree) and never mutates the
// input flowing to downstream nodes.
type Output struct {
	dag_impl.BaseOutput
	RepoPath string `json:"-"`
	Commit   string `json:"commit,omitempty"`
}

func NewOutput(status executiondag.Status, statusReason, repoPath, commit string, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(status, statusReason, input),
		RepoPath:   repoPath,
		Commit:     commit,
	}
}

func (o *Output) PersistKey() string { return "clone_published_content" }
