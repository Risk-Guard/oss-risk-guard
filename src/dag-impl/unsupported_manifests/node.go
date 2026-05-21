package unsupported_manifests

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_content"
	"github.com/Risk-Guard/oss-risk-guard/src/language/unsupported"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type Node struct {
	Description string `json:"description,omitempty"`
}

func NewNode() *Node {
	return &Node{
		Description: "Detects unsupported manifest files in the repository",
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	cloneOut := executiondag.GetOutput[*git_clone_content.Node](ctx).(*git_clone_content.Output)

	manifests, err := unsupported.DetectUnsupportedManifests(cloneOut.RepoPath)
	if err != nil {
		return nil, fmt.Errorf("detecting unsupported manifests: %w", err)
	}

	if len(manifests) == 0 {
		return NewOutput(
			executiondag.StatusSuccess,
			"no unsupported manifest files detected",
			nil,
			input,
		), nil
	}

	return NewOutput(
		executiondag.StatusSuccess,
		fmt.Sprintf("detected %d unsupported manifest file(s)", len(manifests)),
		manifests,
		input,
	), nil
}

func (n *Node) GetDependencies() []any {
	return []any{executiondag.DependsOn[*git_clone_content.Node]()}
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(
		executiondag.StatusSkipped,
		reason,
		nil,
		input,
	)
}

func (n *Node) Kind() string {
	return "transform"
}
