package source_repo_new

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

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "SOURCE_REPO_NEW",
			Description: "Source repository was created recently",
			Disclaimers: []string{
				fmt.Sprintf("Default threshold is %d days.", 365),
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryContinuityAssurance:   "A recently created repository has no track record for stability or long-term maintenance.",
				category.RiskCategorySecurityVulnerability: "New projects lack a proven security track record and may not have sufficient adoption for vulnerabilities to be reported.",
			},
			Thresholds: map[string]any{
				"min_age_days": 365,
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
	if gitMeta.FirstCommit == nil {
		return nil, fmt.Errorf("first commit is nil in git metadata")
	}

	// Perform the actual check - violation if < 365 days old
	minAgeDays := n.Thresholds["min_age_days"].(int)
	daysSinceFirst := int(time.Since(*gitMeta.FirstCommit).Hours() / 24)

	if daysSinceFirst < minAgeDays {
		log.Debug("SOURCE_REPO_NEW check: violation",
			zap.Int("days_since_first", daysSinceFirst),
			zap.Int("threshold", minAgeDays))
		return checks.NewViolationOutput(
			n.Code,
			fmt.Sprintf("Project is %d days old", daysSinceFirst),
			[]string{fmt.Sprintf("First commit: %s", gitMeta.FirstCommit.Format("2006-01-02"))},
			input,
		).WithThresholds(n.Thresholds), nil
	}

	// Compliant - project is old enough
	log.Debug("SOURCE_REPO_NEW check: compliant",
		zap.Int("days_since_first", daysSinceFirst))
	return checks.NewCompliantOutput(
		n.Code,
		fmt.Sprintf("Project is %d days old", daysSinceFirst),
		input,
	).WithThresholds(n.Thresholds), nil
}
