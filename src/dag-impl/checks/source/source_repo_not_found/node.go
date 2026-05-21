package source_repo_not_found

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "SOURCE_REPO_NOT_FOUND",
			Description: "Source repository could not be found or accessed",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryCritical: "Source code cannot be independently verified when the repository cannot be found or accessed.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*git_resolve.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	if input.SourceURL == nil {
		log.Debug("no source URL provided, skipping SOURCE_REPO_NOT_FOUND check")
		return checks.NewSkippedOutput(n.Code, "No source repository specified", input), nil
	}

	resolveOut := executiondag.GetOutput[*git_resolve.Node](ctx).(*git_resolve.Output)

	if resolveOut.GetStatus() == executiondag.StatusSuccess {
		log.Debug("SOURCE_REPO_NOT_FOUND check: compliant")
		return checks.NewCompliantOutput(n.Code, fmt.Sprintf("Source repository found and resolved successfully: %s", *input.SourceURL), input), nil
	}

	rationale := "Source repository could not be found or accessed"

	if resolveOut.GetStatusReason() != "" {
		rationale = fmt.Sprintf("%s - %s", rationale, resolveOut.GetStatusReason())
	}

	log.Debug("SOURCE_REPO_NOT_FOUND check: violation",
		zap.String("rationale", rationale))
	evidence := []string{fmt.Sprintf("URL: %s", *input.SourceURL)}

	if resolveOut.GitErrorDetails != nil && resolveOut.GitErrorDetails.GitOutput != "" {
		evidence = append(evidence, fmt.Sprintf("Git error: %s", resolveOut.GitErrorDetails.GitOutput))
	}

	return checks.NewViolationOutput(n.Code, rationale, evidence, input), nil
}

// AllowAutoSkip implements executiondag.SkipPropagationNode.
// Returns false because this check WANTS to run even when git_resolve is skipped.
func (n *Node) AllowAutoSkip() bool {
	return false
}
