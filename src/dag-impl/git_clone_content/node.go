package git_clone_content

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"github.com/Risk-Guard/oss-risk-guard/src/language/unsupported"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	licpatterns "github.com/Risk-Guard/oss-risk-guard/src/licenses/patterns"
	"github.com/Risk-Guard/oss-risk-guard/src/riskguardignore"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type Node struct {
	isLocal            bool
	ecosystems         []def.Ecosystem
	Description        string `json:"description,omitempty"`
	deps               []any
	sparseCheckoutHash string
}

func NewNode(isLocal bool, deps []any, ecosystems []def.Ecosystem) *Node {
	n := &Node{
		Description: "Clones git repository file content (no commit history) for analysis",
		deps:        deps,
		isLocal:     isLocal,
		ecosystems:  ecosystems,
	}
	n.sparseCheckoutHash = hashPatterns(n.buildSparseCheckoutPatterns())
	return n
}

func (n *Node) buildSparseCheckoutPatterns() []string {
	result := make([]string, 0)
	result = append(result, licpatterns.GitSparseCheckoutPatterns()...)
	result = append(result, git.SparseCheckoutPatterns...)
	result = append(result, unsupported.SparseCheckoutPatterns...)

	for _, analyzer := range n.ecosystems {
		result = append(result, analyzer.GitSparseCheckoutFilePatterns()...)
	}

	return result
}

func hashPatterns(patterns []string) string {
	sorted := make([]string, len(patterns))
	copy(sorted, patterns)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return fmt.Sprintf("%x", h[:6])
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	if !input.HasSourceURL() {
		return NewOutput(
			executiondag.StatusSkipped,
			"no source URL provided",
			"",
			"",
			input,
		), nil
	}

	sourceURL := *input.SourceURL

	resolveOut := executiondag.GetOutput[*git_resolve.Node](ctx).(*git_resolve.Output)

	if n.isLocal {
		return n.handleLocalRepository(ctx, sourceURL, resolveOut, input)
	}

	return n.handleRemoteRepository(ctx, sourceURL, resolveOut, input)
}

func (n *Node) handleLocalRepository(ctx context.Context, sourceURL string, resolveOut *git_resolve.Output, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	logger.Debug("using local path", zap.String("path", sourceURL))

	// A local source's content is the files in the directory; git is not
	// required to read them (commit history is a separate concern resolved by
	// git_resolve / git_clone_metadata). Require only that the path is a
	// readable directory so file-based checks run on any local source, git or
	// not.
	info, err := os.Stat(sourceURL)
	if err != nil {
		return NewOutput(
			executiondag.StatusSkipped,
			fmt.Sprintf("reading local source directory: %v", err),
			"",
			"",
			input,
		), nil
	}
	if !info.IsDir() {
		return NewOutput(
			executiondag.StatusSkipped,
			fmt.Sprintf("local source path is not a directory: %s", sourceURL),
			"",
			"",
			input,
		), nil
	}

	n.applyIgnorePatterns(ctx, sourceURL, input.Trusted)

	commit := resolveOut.Commit

	logger.Debug("prepared local source content", zap.String("path", sourceURL), zap.String("commit", commit))
	return NewOutput(
		executiondag.StatusSuccess,
		"",
		sourceURL,
		commit,
		input,
	), nil
}

func (n *Node) handleRemoteRepository(ctx context.Context, sourceURL string, resolveOut *git_resolve.Output, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)
	backend := cache.GetCacheBackend(ctx)

	normalizedURL := resolveOut.NormalizedURL
	isPrivate := resolveOut.IsPrivate
	commitSHA := resolveOut.Commit

	useCache := !isPrivate && commitSHA != ""
	if useCache {
		out, err := n.tryCloneCache(ctx, backend, normalizedURL, commitSHA, sourceURL, input)
		if err != nil {
			return nil, err
		}
		if out != nil {
			return out, nil
		}
		logger.Debug("clone cache miss", zap.String("source_url", sourceURL), zap.String("commit", commitSHA))
	}

	return n.cloneAndCache(ctx, sourceURL, commitSHA, input, backend, normalizedURL, useCache)
}

func (n *Node) validateClonedRepo(_ context.Context, repoPath string) error {
	_, err := git.ValidateGitRepo(repoPath)
	return err
}

func (n *Node) handleCloneError(err error) error {
	return fmt.Errorf("clone failed after resolve succeeded: %w", err)
}

func (n *Node) executeCloneRemote(ctx context.Context, sourceURL, commitSHA string, input dag_impl.Input) (string, error) {
	logger := ctxutil.GetLogger(ctx)
	cloneCacheDir := runpath.GetCloneCacheDir(ctx)
	repoPath := filepath.Join(cloneCacheDir, input.BasePath(), "repo")

	if err := os.MkdirAll(filepath.Dir(repoPath), 0o750); err != nil {
		return "", fmt.Errorf("creating source directory: %w", err)
	}

	logger.Debug("cloning repository", zap.String("source_url", sourceURL), zap.String("path", repoPath), zap.String("commit", commitSHA))
	patterns := n.buildSparseCheckoutPatterns()
	if err := git.CloneContentOnly(ctx, sourceURL, repoPath, commitSHA, patterns); err != nil {
		return "", fmt.Errorf("cloning repository: %w", err)
	}

	if s, err := repoDirSize(repoPath); err == nil {
		logger.Debug(fmt.Sprintf("clone complete (content: %s, .git: %s, total: %s)",
			humanizeBytes(s.content), humanizeBytes(s.git), humanizeBytes(s.total())),
			zap.String("path", repoPath),
			zap.Int64("content_bytes", s.content),
			zap.Int64("git_bytes", s.git),
			zap.Int64("total_bytes", s.total()))
	}

	return repoPath, nil
}

func (n *Node) GetDependencies() []any {
	return n.deps
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(
		executiondag.StatusSkipped,
		reason,
		"",
		"",
		input,
	)
}

func (n *Node) Kind() string {
	return "fetch"
}

func (n *Node) applyIgnorePatterns(ctx context.Context, repoPath string, trusted bool) {
	if !trusted {
		return
	}

	logger := ctxutil.GetLogger(ctx)
	if err := riskguardignore.ApplyIgnorePatterns(ctx, repoPath); err != nil {
		logger.Warn("failed to apply .riskguardignore", zap.Error(err))
	}
}

func (n *Node) Read(ctx context.Context, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	if !input.HasSourceURL() {
		return NewOutput(
			executiondag.StatusSkipped,
			"no source URL provided",
			"",
			"",
			input,
		), nil
	}

	sourceURL := *input.SourceURL

	logger.Debug("reading cached git clone",
		zap.String("source_url", sourceURL))

	output, err := dag_impl.ReadOutput[*Output](ctx, input)
	if err != nil {
		return nil, fmt.Errorf("reading clone_content.yml: %w", err)
	}

	cloneCacheDir := runpath.GetCloneCacheDir(ctx)
	repoPath := filepath.Join(cloneCacheDir, input.BasePath(), "repo")

	if _, err := os.Stat(repoPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("cached repository not found: %s (expected at: %s)", sourceURL, repoPath)
		}
		return nil, fmt.Errorf("checking cached repository: %w", err)
	}

	output.RepoPath = repoPath

	n.applyIgnorePatterns(ctx, repoPath, input.Trusted)

	logger.Debug("verified cached git repository",
		zap.String("source_url", sourceURL),
		zap.String("path", repoPath),
		zap.String("commit", output.Commit))

	return output, nil
}
