package source_repo_abandoned

import (
	"context"
	"fmt"
	"risk-guard/src/category"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/dag-impl/git_clone_metadata"
	"time"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

const (
	CheckCode       = "SOURCE_REPO_ABANDONED"
	LegacyThreshold = 1825 // 5 years in days
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "SOURCE_REPO_ABANDONED",
			Description: "Source repository has had no human commits for an extended period",
			Disclaimers: []string{
				"Bot commits are excluded.",
				fmt.Sprintf("Default threshold is %d days.", LegacyThreshold),
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryContinuityAssurance:   "An abandoned project will not accept bug fixes or compatibility updates.",
				category.RiskCategorySecurityVulnerability: "An abandoned project will not receive security patches.",
			},
			Thresholds: map[string]any{
				"legacy_days": LegacyThreshold,
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

	if gitMeta.LatestHumanCommit == nil {
		return nil, fmt.Errorf("latest human commit is nil in git metadata")
	}

	// Calculate days since last commit
	daysSinceLast := int(time.Since(*gitMeta.LatestHumanCommit).Hours() / 24)

	// Check if last commit is over the threshold
	legacyDays := n.Thresholds["legacy_days"].(int)
	if daysSinceLast > legacyDays {
		log.Debug("SOURCE_REPO_ABANDONED check: violation",
			zap.Int("days_since_last", daysSinceLast),
			zap.Int("threshold", legacyDays))

		evidence := []string{
			fmt.Sprintf("Latest human commit: %s", gitMeta.LatestHumanCommit.Format("2006-01-02")),
		}

		return checks.NewViolationOutput(
			n.Code,
			fmt.Sprintf("Last repository commit was %d days ago", daysSinceLast),
			evidence,
			input,
		).WithThresholds(n.Thresholds), nil
	}

	// Repository is active
	log.Debug("SOURCE_REPO_ABANDONED check: compliant",
		zap.Int("days_since_last", daysSinceLast))

	return checks.NewCompliantOutput(
		n.Code,
		fmt.Sprintf("Last repository commit was %d days ago", daysSinceLast),
		input,
	).WithThresholds(n.Thresholds), nil
}
