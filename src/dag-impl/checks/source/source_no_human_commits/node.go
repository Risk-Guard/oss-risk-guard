package source_no_human_commits

import (
	"context"
	"fmt"
	"risk-guard/src/category"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/dag-impl/git_clone_metadata"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "SOURCE_NO_HUMAN_COMMITS",
			Description: "Repository has no human commits",
			Disclaimers: []string{
				"Bot commits are excluded.",
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryContinuityAssurance:   "A repository with no human commit history raises doubt about whether this is the correct source repository.",
				category.RiskCategorySecurityVulnerability: "A package published from a repository with no human commits raises supply chain integrity concerns.",
				category.RiskCategoryTitleAssurance:        "Absence of human commits weakens confidence that this repository is the true source for the package.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*git_clone_metadata.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	metaOut := executiondag.GetOutput[*git_clone_metadata.Node](ctx).(*git_clone_metadata.Output)
	gitMeta := metaOut.GitMetadata()

	if gitMeta == nil {
		return nil, fmt.Errorf("git metadata is nil despite git_clone_metadata success")
	}

	humanCommitCount := 0
	if gitMeta.HumanCommitCount != nil {
		humanCommitCount = *gitMeta.HumanCommitCount
	}

	if humanCommitCount == 0 {
		log.Debug("SOURCE_NO_HUMAN_COMMITS check: violation")
		return checks.NewViolationOutput(
			n.Code,
			"Repository has no human commits",
			nil,
			input,
		), nil
	}

	log.Debug("SOURCE_NO_HUMAN_COMMITS check: compliant",
		zap.Int("human_commit_count", humanCommitCount))
	return checks.NewCompliantOutput(
		n.Code,
		fmt.Sprintf("Repository has %d human commits", humanCommitCount),
		input,
	), nil
}
