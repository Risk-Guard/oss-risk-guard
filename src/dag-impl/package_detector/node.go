package package_detector

import (
	"context"
	"fmt"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/git_clone_content"
	"risk-guard/src/ecosystem/def"
	"risk-guard/src/package_detection"

	"go.uber.org/zap"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
)

type Node struct {
	Description string `json:"description,omitempty"`
	ecosystems  []def.Ecosystem
}

func NewNode(ecosystems []def.Ecosystem) *Node {
	return &Node{
		Description: "Detects all packages defined in a source directory. Supports Python (pyproject.toml, setup.py) and NPM (package.json)",
		ecosystems:  ecosystems,
	}
}

// Execute detects packages in the repository.
// Returns Output with detected packages that will be merged into input for downstream nodes.
func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	// Get clone output from context (guaranteed to exist and be successful by DAG)
	cloneOut := executiondag.GetOutput[*git_clone_content.Node](ctx).(*git_clone_content.Output)

	// Get repository path from clone output
	repoPath := cloneOut.RepoPath

	logger.Info("detecting packages in repository", zap.String("path", repoPath))
	detectedPkgs, err := package_detection.DetectPackages(repoPath, n.ecosystems)
	if err != nil {
		return nil, fmt.Errorf("detecting packages: %w", err)
	}

	enrichedPkgs := enrichManifests(detectedPkgs, repoPath, input.AnalysisIdentifier)

	logger.Info("detected packages",
		zap.Int("count", len(enrichedPkgs)))

	// Success - return detected packages
	return NewOutput(
		executiondag.StatusSuccess,
		fmt.Sprintf("detected %d package(s)", len(enrichedPkgs)),
		enrichedPkgs,
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
