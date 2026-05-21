package org_security_policy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"

	"go.uber.org/zap"

	riskhttp "github.com/Risk-Guard/oss-risk-guard/src/http"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

var rawGitHubBaseURL = "https://raw.githubusercontent.com"

type Node struct {
	Description string                         `json:"description,omitempty"`
	Sources     map[string]executiondag.Source `json:"sources"`
}

func NewNode() *Node {
	return &Node{
		Description: "Checks for a SECURITY.md in the GitHub owner-level .github repository",
		Sources: map[string]executiondag.Source{
			"raw.githubusercontent.com": {
				Name:        "GitHub Raw Content",
				Description: "HTTP HEAD check for owner-level SECURITY.md via raw.githubusercontent.com",
				URL:         "https://raw.githubusercontent.com",
				Category:    executiondag.SourceCategoryReference,
			},
		},
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	if !input.HasSourceURL() {
		return NewOutput(executiondag.StatusSuccess, "no source URL provided", false, "", input), nil
	}

	sourceURL := input.MustHaveSourceURL()

	parsed, err := url.Parse(sourceURL)
	if err != nil || parsed.Host != "github.com" {
		return NewOutput(executiondag.StatusSuccess, "not a GitHub source", false, "", input), nil
	}

	org, _, ok := common.ExtractOwnerRepo(parsed.Path)
	if !ok {
		return NewOutput(executiondag.StatusSuccess, "could not extract owner from source URL", false, "", input), nil
	}

	client := riskhttp.DefaultHTTPClient()

	for _, branch := range []string{"main", "master"} {
		for _, filename := range []string{"SECURITY.md", "security.md"} {
			checkURL := fmt.Sprintf("%s/%s/.github/%s/%s", rawGitHubBaseURL, org, branch, filename)

			req, err := http.NewRequestWithContext(ctx, http.MethodHead, checkURL, nil)
			if err != nil {
				logger.Debug("failed to create request for org security policy", zap.Error(err))
				return NewOutput(executiondag.StatusSuccess, "failed to create HTTP request", false, "", input), nil
			}

			if token := ctxutil.GetSourceToken(ctx); token != "" {
				req.Header.Set("Authorization", "token "+token)
			}

			resp, err := client.Do(req) //nolint:gosec // URL constructed from validated org name and fixed path segments
			if err != nil {
				logger.Debug("org security policy HTTP request failed", zap.Error(err))
				return NewOutput(executiondag.StatusSuccess, "HTTP request failed", false, "", input), nil
			}
			_ = resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				policyPath := fmt.Sprintf("%s/.github/%s", org, filename)
				return NewOutput(executiondag.StatusSuccess,
					fmt.Sprintf("org-level security policy found at %s", policyPath),
					true, policyPath, input,
				).WithSources(n.Sources), nil
			}
		}
	}

	return NewOutput(executiondag.StatusSuccess, "no org-level security policy found", false, "", input).WithSources(n.Sources), nil
}

func (n *Node) GetDependencies() []any {
	return []any{executiondag.DependsOn[*git_resolve.Node]()}
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, false, "", input)
}

func (n *Node) GetSources() map[string]executiondag.Source { return n.Sources }

func (n *Node) Kind() string {
	return "fetch"
}

func (n *Node) Read(ctx context.Context, input dag_impl.Input) (*Output, error) {
	output, err := dag_impl.ReadOutput[*Output](ctx, input)
	if err != nil {
		return NewOutput(executiondag.StatusSuccess, "org security policy data not available in cache", false, "", input), nil
	}
	return output, nil
}
