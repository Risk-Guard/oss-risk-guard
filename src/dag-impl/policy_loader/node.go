package policy_loader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_content"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// Node loads and resolves .risk-guard.yml policy from the cloned repository
type Node struct {
	Description string `json:"description,omitempty"`
}

// NewNode creates a new policy loader node
func NewNode() *Node {
	return &Node{
		Description: "Loads and resolves .risk-guard.yml policy from repository",
	}
}

// GetDependencies returns the node dependencies - requires git_clone_content to have completed
func (n *Node) GetDependencies() []any {
	return []any{executiondag.DependsOn[*git_clone_content.Node]()}
}

// Execute loads the policy from the cloned repository
func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	log := ctxutil.GetLogger(ctx)

	// Get git_clone_content output to find repo path
	gitCloneOut := executiondag.GetOutput[*git_clone_content.Node](ctx).(*git_clone_content.Output)

	if gitCloneOut.GetStatus() == executiondag.StatusSkipped {
		return NewOutput(
			executiondag.StatusSkipped,
			"git_clone_content was skipped: "+gitCloneOut.GetStatusReason(),
			nil,
			"",
			nil,
			input,
		), nil
	}

	repoPath := gitCloneOut.RepoPath
	if repoPath == "" {
		return NewOutput(
			executiondag.StatusSkipped,
			"git_clone_content output has empty repo path",
			nil,
			"",
			nil,
			input,
		), nil
	}

	// Load policy from repository
	policyPath := filepath.Join(repoPath, policy.PolicyFileName)
	rawYAML, err := os.ReadFile(policyPath) //nolint:gosec // path is derived from git clone
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug("no .risk-guard.yml found, using default policy",
				zap.String("repo", repoPath))
			return NewOutput(executiondag.StatusSuccess, "", policy.DefaultPolicy(), policy.DefaultPolicyYAML(), nil, input), nil
		}
		return nil, fmt.Errorf("reading policy file %s: %w", policyPath, err)
	}

	result, err := policy.LoadFullFromBytes(rawYAML, policyPath)
	if err != nil {
		errMsg := fmt.Sprintf("loading policy from %s: %v", repoPath, err)
		log.Warn("policy file error, evaluation will return FAILED status",
			zap.String("repo", repoPath),
			zap.Error(err))
		return NewOutputWithError(errMsg, input), nil
	}

	if result.Policy.Workflow != nil && result.Policy.Workflow.Mode == policy.WorkflowModeDisabled {
		log.Debug("workflow disabled by policy",
			zap.String("repo", repoPath))
		return nil, fmt.Errorf("workflow disabled by policy")
	}

	workflowMode := policy.WorkflowModeActive
	if result.Policy.Workflow != nil && result.Policy.Workflow.Mode != "" {
		workflowMode = result.Policy.Workflow.Mode
	}

	log.Debug("policy loaded successfully",
		zap.Int("rules", len(result.Policy.Rules)),
		zap.Int("expected_failures", len(result.Policy.ExpectedFailures)),
		zap.String("workflow_mode", string(workflowMode)))

	return NewOutput(executiondag.StatusSuccess, "", result.Policy, string(rawYAML), result.Overrides, input), nil
}

// CreateSkippedOutput creates a skipped output with the given reason
func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, nil, "", nil, input)
}

// Kind returns the node kind
func (n *Node) Kind() string {
	return "transform"
}
