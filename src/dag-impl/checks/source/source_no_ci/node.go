package source_no_ci

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"risk-guard/src/category"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/dag-impl/git_clone_content"
	"risk-guard/src/git"
	"sort"
	"strings"

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
			Code:        "SOURCE_NO_CI",
			Description: "No continuous integration configuration found in source repository",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryContinuityAssurance:   "Without CI, there are no automated quality gates on code changes.",
				category.RiskCategorySecurityVulnerability: "Without CI, there are no automated security gates on code changes.",
			},
			Disclaimers: []string{
				"Checks for the presence of CI configuration files, not whether pipelines are active or passing.",
				fmt.Sprintf("Supported providers: %s.", strings.Join(ciProviderNames(), ", ")),
			},
		},
	}
}

func ciProviderNames() []string {
	names := make([]string, 0, len(git.CIProviders))
	for name := range git.CIProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*git_clone_content.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	gitOut := executiondag.GetOutput[*git_clone_content.Node](ctx).(*git_clone_content.Output)
	repoPath := gitOut.RepoPath

	if repoPath == "" {
		return nil, fmt.Errorf("repo path is empty despite git_clone_content success")
	}

	for _, serviceName := range ciProviderNames() {
		provider := git.CIProviders[serviceName]
		found, path, err := detectProvider(repoPath, provider)
		if err != nil {
			return nil, err
		}
		if found {
			log.Debug("SOURCE_NO_CI check: compliant",
				zap.String("service", serviceName),
				zap.String("path", path))
			return checks.NewCompliantOutput(
				n.Code,
				fmt.Sprintf("CI configuration found: %s (%s)", serviceName, path),
				input,
			), nil
		}
	}

	log.Debug("SOURCE_NO_CI check: violation")
	return checks.NewViolationOutput(
		n.Code,
		"No CI configuration found",
		nil,
		input,
	), nil
}

func detectProvider(repoPath string, provider git.CIProvider) (bool, string, error) {
	for _, candidate := range provider.Paths {
		fullPath := filepath.Join(repoPath, candidate)
		info, err := os.Stat(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, "", fmt.Errorf("checking CI config %s: %w", candidate, err)
		}
		if info.IsDir() {
			if hasYAMLFiles(fullPath) {
				return true, candidate, nil
			}
			continue
		}
		return true, candidate, nil
	}
	return false, "", nil
}

func hasYAMLFiles(dirPath string) bool {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			return true
		}
	}
	return false
}
