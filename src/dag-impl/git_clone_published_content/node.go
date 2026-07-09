package git_clone_published_content

import (
	"context"
	"fmt"
	"os"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_content"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// repoDirName is deliberately distinct from git_clone_content's "repo" so the
// published-version tree and the HEAD tree never clobber each other on disk.
const repoDirName = "repo-published"

// Node clones the source tree at the analyzed version's gitHead — the commit the
// package was published from — for provenance checks that must compare the
// published artifact against its source as-published rather than current HEAD.
// It is a no-op (skipped) whenever no usable gitHead is available, in which case
// downstream provenance checks fall back to the HEAD clone.
type Node struct {
	isLocal            bool
	ecosystems         []def.Ecosystem
	Description        string `json:"description,omitempty"`
	deps               []any
	sparseCheckoutHash string
}

func NewNode(isLocal bool, deps []any, ecosystems []def.Ecosystem) *Node {
	return &Node{
		Description:        "Clones the source tree at the published version's gitHead commit for provenance checks",
		deps:               deps,
		isLocal:            isLocal,
		ecosystems:         ecosystems,
		sparseCheckoutHash: git_clone_content.HashPatterns(git_clone_content.BuildSparsePatterns(ecosystems)),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	log := ctxutil.GetLogger(ctx)

	if !input.HasSourceURL() {
		return NewOutput(executiondag.StatusSkipped, "no source URL provided", "", "", input), nil
	}
	// gitHead is a registry (e.g. npm) concept for a remotely-published version;
	// a local source has no published commit to pin to.
	if n.isLocal {
		return NewOutput(executiondag.StatusSkipped, "local source has no published gitHead", "", "", input), nil
	}

	gitHead := selectGitHead(ctx, input)
	if gitHead == "" {
		return NewOutput(executiondag.StatusSkipped, "no gitHead available for analyzed version", "", "", input), nil
	}

	resolveOut := executiondag.GetOutput[*git_resolve.Node](ctx).(*git_resolve.Output)

	m, err := git_clone_content.Materialize(ctx, git_clone_content.MaterializeParams{
		SourceURL:          *input.SourceURL,
		IsLocal:            false,
		CommitSHA:          gitHead,
		RepoDirName:        repoDirName,
		SparseCheckoutHash: n.sparseCheckoutHash,
		Patterns:           git_clone_content.BuildSparsePatterns(n.ecosystems),
		NormalizedURL:      resolveOut.NormalizedURL,
		IsPrivate:          resolveOut.IsPrivate,
		Trusted:            input.Trusted,
	}, input)
	if err != nil {
		// A gitHead that no longer resolves on the remote (force-push, deleted
		// branch, unadvertised SHA) is a source-owner data problem, not a fatal
		// error. Skip so the published detector falls back to HEAD instead of
		// halting the DAG.
		log.Info("published gitHead clone failed; provenance checks will fall back to HEAD",
			zap.String("git_head", gitHead), zap.Error(err))
		return NewOutput(executiondag.StatusSkipped,
			fmt.Sprintf("cloning published gitHead %s: %v", gitHead, err), "", "", input), nil
	}

	return NewOutput(m.Status, m.Reason, m.RepoPath, m.Commit, input), nil
}

// selectGitHead returns the gitHead of the analyzed package's version when the
// registry recorded one and it is a full SHA (the only form git can fetch by).
// The DAG is scoped to a single source URL, so the first package carrying a
// usable gitHead identifies the published commit for that source.
func selectGitHead(ctx context.Context, input dag_impl.Input) string {
	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)
	for _, pkg := range input.Packages {
		meta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name)
		if meta == nil || meta.GitHead == nil {
			continue
		}
		if git.IsFullSHA(*meta.GitHead) {
			return *meta.GitHead
		}
	}
	return ""
}

func (n *Node) GetDependencies() []any { return n.deps }

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, "", "", input)
}

func (n *Node) Kind() string { return "fetch" }

func (n *Node) Read(ctx context.Context, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	output, err := dag_impl.ReadOutput[*Output](ctx, input)
	if err != nil {
		// Nothing persisted (e.g. the fetch run had no gitHead and skipped this
		// node). Treat as skipped so the published detector falls back to HEAD.
		return NewOutput(executiondag.StatusSkipped, "no published clone available", "", "", input), nil
	}

	if output.GetStatus() != executiondag.StatusSuccess {
		return output, nil
	}

	repoPath := git_clone_content.RepoWorkPath(ctx, input, repoDirName)
	if _, statErr := os.Stat(repoPath); statErr != nil {
		return NewOutput(executiondag.StatusSkipped, "published clone directory not found", "", "", input), nil
	}
	output.RepoPath = repoPath

	logger.Debug("verified cached published clone",
		zap.String("path", repoPath), zap.String("commit", output.Commit))
	return output, nil
}
