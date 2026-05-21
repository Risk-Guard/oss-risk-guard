package source_repo_stale

import (
	"context"
	"fmt"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

const (
	CheckCode       = "SOURCE_REPO_STALE"
	StaleDays       = 365
	FiveYearsInDays = 1825
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        CheckCode,
			Description: "Source repository has had no human commits for a significant period",
			Disclaimers: []string{
				"Bot commits are excluded.",
				fmt.Sprintf("Default threshold is %d days.", StaleDays),
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryContinuityAssurance:   "A stale project may not accept bug fixes or compatibility updates.",
				category.RiskCategorySecurityVulnerability: "A stale project may not receive timely security patches.",
			},
			Thresholds: map[string]any{
				"stale_days": StaleDays,
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
		return checks.NewSkippedOutput(n.Code, "No human commit history available", input), nil
	}

	// Calculate days since last commit
	daysSinceLast := int(time.Since(*gitMeta.LatestHumanCommit).Hours() / 24)

	// Only fail if over 1 year but not over 5 years (that's a different check)
	staleDays := n.Thresholds["stale_days"].(int)
	if daysSinceLast > staleDays && daysSinceLast <= FiveYearsInDays {
		log.Debug("SOURCE_REPO_STALE check: violation",
			zap.Int("days_since_last", daysSinceLast),
			zap.Int("threshold", staleDays))

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

	// If over 5 years, skip (let the 5-year check handle it)
	if daysSinceLast > FiveYearsInDays {
		log.Debug("SOURCE_REPO_STALE check: skipped (over 5 years)",
			zap.Int("days_since_last", daysSinceLast))
		return n.CreateSkippedOutput("Last commit is over 5 years old (handled by different check)", input), nil
	}

	// Repository is active
	log.Debug("SOURCE_REPO_STALE check: compliant",
		zap.Int("days_since_last", daysSinceLast))

	return checks.NewCompliantOutput(
		n.Code,
		fmt.Sprintf("Last repository commit was %d days ago", daysSinceLast),
		input,
	).WithThresholds(n.Thresholds), nil
}
