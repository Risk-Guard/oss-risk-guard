package source_single_contributor

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_repo_abandoned"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_repo_stale"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

const (
	minAuthors = 1
	recentDays = 365
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "SOURCE_SINGLE_CONTRIBUTOR",
			Description: "Source repository has a single recent contributor",
			Disclaimers: []string{
				fmt.Sprintf("Default threshold: %d author(s) in the last %d days.", minAuthors, recentDays),
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryContinuityAssurance:   "A single contributor represents a single point of failure for ongoing maintenance.",
				category.RiskCategorySecurityVulnerability: "A single reviewer provides no independent code review, and maintainer burnout increases susceptibility to social engineering attacks.",
			},
			Thresholds: map[string]any{
				"min_authors": minAuthors,
				"recent_days": recentDays,
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*git_clone_metadata.Node](),
		executiondag.DependsOn[*source_repo_stale.Node](),
		executiondag.DependsOn[*source_repo_abandoned.Node](),
	}
}

func (n *Node) AllowAutoSkip() bool {
	return false
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	staleOut := executiondag.GetOutput[*source_repo_stale.Node](ctx).(*checks.Output)
	abandonedOut := executiondag.GetOutput[*source_repo_abandoned.Node](ctx).(*checks.Output)

	if staleOut.Check.CheckStatus == storage.StatusViolation {
		log.Debug("SOURCE_SINGLE_CONTRIBUTOR check: skipped (repo is stale)")
		return n.CreateSkippedOutput("Deferred to SOURCE_REPO_STALE", input), nil
	}
	if abandonedOut.Check.CheckStatus == storage.StatusViolation {
		log.Debug("SOURCE_SINGLE_CONTRIBUTOR check: skipped (repo is abandoned)")
		return n.CreateSkippedOutput("Deferred to SOURCE_REPO_ABANDONED", input), nil
	}

	metaOut := executiondag.GetOutput[*git_clone_metadata.Node](ctx).(*git_clone_metadata.Output)
	if metaOut.GetStatus() == executiondag.StatusSkipped {
		return n.CreateSkippedOutput("git clone metadata was skipped", input), nil
	}

	gitMeta := metaOut.GitMetadata()
	if gitMeta == nil {
		return nil, fmt.Errorf("git metadata is nil despite git_clone_metadata success")
	}

	if gitMeta.RecentAuthorsCount == nil {
		return nil, fmt.Errorf("recent authors count is nil in git metadata")
	}

	authorCount := *gitMeta.RecentAuthorsCount
	minAuthors := n.Thresholds["min_authors"].(int)
	recentDays := n.Thresholds["recent_days"].(int)

	// Check for single point of failure (too few authors)
	if authorCount <= minAuthors {
		log.Debug("SOURCE_SINGLE_CONTRIBUTOR check: violation",
			zap.Int("author_count", authorCount),
			zap.Int("min_authors", minAuthors))
		return checks.NewViolationOutput(
			n.Code,
			fmt.Sprintf("Authors in last %d days: %d", recentDays, authorCount),
			nil,
			input,
		).WithThresholds(n.Thresholds), nil
	}

	// Repository has sufficient authors
	log.Debug("SOURCE_SINGLE_CONTRIBUTOR check: compliant",
		zap.Int("author_count", authorCount),
		zap.Int("min_authors", minAuthors))
	return checks.NewCompliantOutput(
		n.Code,
		fmt.Sprintf("%d authors in last %d days", authorCount, recentDays),
		input,
	).WithThresholds(n.Thresholds), nil
}
