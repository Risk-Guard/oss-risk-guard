package source_no_security_policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_content"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/org_security_policy"
	"github.com/Risk-Guard/oss-risk-guard/src/git"

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
			Code:        "SOURCE_NO_SECURITY_POLICY",
			Description: "No security policy found in source repository",
			Categories: map[category.RiskCategory]string{
				category.RiskCategorySecurityVulnerability: "Absence of a disclosure channel increases risk of uncoordinated vulnerability disclosure.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*git_clone_content.Node](),
		executiondag.DependsOn[*org_security_policy.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	gitOut := executiondag.GetOutput[*git_clone_content.Node](ctx).(*git_clone_content.Output)
	repoPath := gitOut.RepoPath

	if repoPath == "" {
		return nil, fmt.Errorf("repo path is empty despite git_clone_content success")
	}

	for _, candidate := range git.SecurityPolicyPaths {
		fullPath := filepath.Join(repoPath, candidate)
		_, err := os.Stat(fullPath)
		if err == nil {
			log.Debug("SOURCE_NO_SECURITY_POLICY check: compliant",
				zap.String("found", candidate))
			return checks.NewCompliantOutput(
				n.Code,
				fmt.Sprintf("Security policy found: %s", candidate),
				input,
			), nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("checking security policy file %s: %w", candidate, err)
		}
	}

	orgOut := executiondag.GetOutput[*org_security_policy.Node](ctx).(*org_security_policy.Output)
	if orgOut.Found {
		log.Debug("SOURCE_NO_SECURITY_POLICY check: compliant (org-level)")
		return checks.NewCompliantOutput(n.Code,
			fmt.Sprintf("Security policy found: %s (org-level)", orgOut.PolicyPath), input), nil
	}

	log.Debug("SOURCE_NO_SECURITY_POLICY check: violation")
	return checks.NewViolationOutput(
		n.Code,
		"No security policy file found",
		nil,
		input,
	), nil
}
