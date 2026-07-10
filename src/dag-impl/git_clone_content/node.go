package git_clone_content

import (
	"context"
	"fmt"
	"os"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// repoDirName is the working-tree subdirectory this node checks out into. The
// published-version clone uses a different name so the two never collide.
const repoDirName = "repo"

type Node struct {
	isLocal            bool
	ecosystems         []def.Ecosystem
	Description        string `json:"description,omitempty"`
	deps               []any
	sparseCheckoutHash string
}

func NewNode(isLocal bool, deps []any, ecosystems []def.Ecosystem) *Node {
	return &Node{
		Description:        "Clones git repository file content (no commit history) for analysis",
		deps:               deps,
		isLocal:            isLocal,
		ecosystems:         ecosystems,
		sparseCheckoutHash: HashPatterns(BuildSparsePatterns(ecosystems)),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	if !input.HasSourceURL() {
		return NewOutput(executiondag.StatusSkipped, "no source URL provided", "", "", input), nil
	}

	sourceURL := *input.SourceURL
	resolveOut := executiondag.GetOutput[*git_resolve.Node](ctx).(*git_resolve.Output)

	m, err := Materialize(ctx, MaterializeParams{
		SourceURL:          sourceURL,
		IsLocal:            n.isLocal,
		CommitSHA:          resolveOut.Commit,
		RepoDirName:        repoDirName,
		SparseCheckoutHash: n.sparseCheckoutHash,
		Patterns:           BuildSparsePatterns(n.ecosystems),
		NormalizedURL:      resolveOut.NormalizedURL,
		IsPrivate:          resolveOut.IsPrivate,
		Trusted:            input.Trusted,
	}, input)
	if err != nil {
		return nil, err
	}

	return NewOutput(m.Status, m.Reason, m.RepoPath, m.Commit, input), nil
}

func (n *Node) GetDependencies() []any {
	return n.deps
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, "", "", input)
}

func (n *Node) Kind() string {
	return "fetch"
}

func (n *Node) Read(ctx context.Context, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	if !input.HasSourceURL() {
		return NewOutput(executiondag.StatusSkipped, "no source URL provided", "", "", input), nil
	}

	sourceURL := *input.SourceURL

	logger.Debug("reading cached git clone", zap.String("source_url", sourceURL))

	output, err := dag_impl.ReadOutput[*Output](ctx, input)
	if err != nil {
		return nil, fmt.Errorf("reading clone_content.yml: %w", err)
	}

	repoPath := RepoWorkPath(ctx, input, repoDirName)

	if _, err := os.Stat(repoPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("cached repository not found: %s (expected at: %s)", sourceURL, repoPath)
		}
		return nil, fmt.Errorf("checking cached repository: %w", err)
	}

	output.RepoPath = repoPath

	applyIgnorePatterns(ctx, repoPath, input.Trusted)

	logger.Debug("verified cached git repository",
		zap.String("source_url", sourceURL),
		zap.String("path", repoPath),
		zap.String("commit", output.Commit))

	return output, nil
}
