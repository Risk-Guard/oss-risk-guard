package license_files

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_content"
	"github.com/Risk-Guard/oss-risk-guard/src/licenses"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type Node struct {
	Description string `json:"description,omitempty"`
}

func NewNode() *Node {
	return &Node{
		Description: "Scans repository for LICENSE, COPYING, and similar files",
	}
}

func (n *Node) GetDependencies() []any {
	return []any{executiondag.DependsOn[*git_clone_content.Node]()}
}

// Execute scans the cloned repository for candidate license files. SPDX matching
// happens downstream in license_spdx_matcher.
func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	log := ctxutil.GetLogger(ctx)

	gitCloneOut := executiondag.GetOutput[*git_clone_content.Node](ctx).(*git_clone_content.Output)
	repoPath := gitCloneOut.RepoPath

	if repoPath == "" {
		return nil, fmt.Errorf("git_clone_content output has empty repo path")
	}

	log.Debug("scanning for license files", zap.String("path", repoPath))
	files, err := licenses.ScanLicenseFiles(repoPath)
	if err != nil {
		return nil, fmt.Errorf("scanning license files: %w", err)
	}

	log.Debug("license scanning complete", zap.Int("file_count", len(files)))

	return NewOutput(
		executiondag.StatusSuccess,
		"",
		files,
		input,
	), nil
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(
		executiondag.StatusSkipped,
		reason,
		[]models.LicenseFile{},
		input,
	)
}

func (n *Node) Kind() string {
	return "transform"
}
