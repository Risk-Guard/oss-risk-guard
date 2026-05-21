package source_few_contributors

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"

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
			Code:        "SOURCE_FEW_CONTRIBUTORS",
			Description: "Source repository has fewer than the required number of unique contributors across its history",
			Disclaimers: []string{
				"Uses peak 30-day rolling window author count across repository history.",
				fmt.Sprintf("Default threshold is %d authors.", 3),
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryContinuityAssurance:   "Few contributors create higher bus-factor risk, making bug fixes and change requests harder to obtain if maintainers leave.",
				category.RiskCategorySecurityVulnerability: "Limited peer review increases the chance that vulnerabilities go unnoticed.",
			},
			Thresholds: map[string]any{
				"author_threshold": 3,
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

	if gitMeta.MaxMonthlyAuthorsCount == nil {
		return nil, fmt.Errorf("max monthly authors count is nil in git metadata")
	}

	threshold := n.Thresholds["author_threshold"].(int)
	authorCount := *gitMeta.MaxMonthlyAuthorsCount

	windowDates := ""
	if gitMeta.MaxMonthlyWindowStart != nil && gitMeta.MaxMonthlyWindowEnd != nil {
		windowDates = fmt.Sprintf(" (window: %s to %s)",
			gitMeta.MaxMonthlyWindowStart.Format("2006-01-02"),
			gitMeta.MaxMonthlyWindowEnd.Format("2006-01-02"))
	}

	// Check for bus factor risk (fewer than threshold authors)
	if authorCount < threshold {
		log.Debug("SOURCE_FEW_CONTRIBUTORS check: violation",
			zap.Int("author_count", authorCount),
			zap.Int("threshold", threshold))
		return checks.NewViolationOutput(
			n.Code,
			fmt.Sprintf("Peak 30-day window authors: %d%s", authorCount, windowDates),
			nil,
			input,
		).WithThresholds(n.Thresholds), nil
	}

	// Repository has sufficient author diversity
	log.Debug("SOURCE_FEW_CONTRIBUTORS check: compliant",
		zap.Int("author_count", authorCount),
		zap.Int("threshold", threshold))
	return checks.NewCompliantOutput(
		n.Code,
		fmt.Sprintf("%d authors in peak 30-day window%s", authorCount, windowDates),
		input,
	).WithThresholds(n.Thresholds), nil
}
