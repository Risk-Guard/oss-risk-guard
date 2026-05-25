package git_clone_content

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func (n *Node) tryCloneCache(ctx context.Context, backend cache.Backend, normalizedURL, commitSHA, sourceURL string, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	tarPath, hit, err := git.GetCachedClone(ctx, backend, n.sparseCheckoutHash, normalizedURL, commitSHA)
	if err != nil {
		return nil, fmt.Errorf("checking clone cache: %w", err)
	}
	if !hit {
		return nil, nil
	}

	cloneCacheDir := runpath.GetCloneCacheDir(ctx)
	repoPath := filepath.Join(cloneCacheDir, input.BasePath(), "repo")
	if err := git.ExtractCachedRepo(tarPath, repoPath); err != nil {
		git.CleanupTarFile(tarPath)
		return nil, fmt.Errorf("extracting cached clone: %w", err)
	}
	git.CleanupTarFile(tarPath)

	n.applyIgnorePatterns(ctx, repoPath, input.Trusted)

	logger.Info("clone cache hit",
		zap.String("source_url", sourceURL),
		zap.String("commit", commitSHA))

	return NewOutput(executiondag.StatusSuccess, "", repoPath, commitSHA, input), nil
}

func (n *Node) cloneAndCache(ctx context.Context, sourceURL, commitSHA string, input dag_impl.Input, backend cache.Backend, normalizedURL string, shouldCache bool) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	repoPath, err := n.executeCloneRemote(ctx, sourceURL, commitSHA, input)
	if err != nil {
		return nil, n.handleCloneError(err)
	}

	if repoPath == "" {
		return NewOutput(
			executiondag.StatusSkipped,
			"unexpected: executeCloneRemote returned empty repoPath without error",
			"", "", input,
		), nil
	}

	if err := n.validateClonedRepo(ctx, repoPath); err != nil {
		return NewOutput(
			executiondag.StatusSkipped,
			fmt.Sprintf("validating cloned git repository: %v", err),
			"", "", input,
		), nil
	}

	commit, err := git.GetHeadCommit(repoPath)
	if err != nil {
		return nil, fmt.Errorf("getting HEAD commit: %w", err)
	}

	gitDir := filepath.Join(repoPath, ".git")
	if err := os.RemoveAll(gitDir); err != nil {
		return nil, fmt.Errorf("removing .git directory: %w", err)
	}

	if shouldCache {
		if err := git.PutCachedClone(ctx, backend, n.sparseCheckoutHash, normalizedURL, commit, repoPath); err != nil {
			return nil, fmt.Errorf("storing clone in cache: %w", err)
		}
	}

	n.applyIgnorePatterns(ctx, repoPath, input.Trusted)

	logger.Debug("cloned git repository", zap.String("path", repoPath), zap.String("commit", commit))
	return NewOutput(executiondag.StatusSuccess, "", repoPath, commit, input), nil
}
