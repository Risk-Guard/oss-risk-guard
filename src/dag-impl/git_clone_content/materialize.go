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

// MaterializeParams describes a single content-only checkout. It is the shared
// input behind the default HEAD clone (git_clone_content) and the
// published-version clone; the two differ only in CommitSHA and RepoDirName.
type MaterializeParams struct {
	SourceURL          string
	IsLocal            bool
	CommitSHA          string // commit to check out; "" means the remote's default HEAD
	RepoDirName        string // working-tree subdirectory under input.BasePath()
	SparseCheckoutHash string
	Patterns           []string
	NormalizedURL      string
	IsPrivate          bool
	Trusted            bool
}

// Materialized is the low-level result of a checkout, before it is wrapped in a
// node-specific Output.
type Materialized struct {
	RepoPath string
	Commit   string
	Status   executiondag.Status
	Reason   string
}

func materializedSkip(reason string) Materialized {
	return Materialized{Status: executiondag.StatusSkipped, Reason: reason}
}

func materializedSuccess(repoPath, commit string) Materialized {
	return Materialized{Status: executiondag.StatusSuccess, RepoPath: repoPath, Commit: commit}
}

// Materialize produces a content-only checkout of p.SourceURL at p.CommitSHA and
// returns its on-disk path. Callers wrap the result in their own Output type so a
// second clone node (e.g. the published-version tree) can share this core while
// persisting under its own key and working directory.
func Materialize(ctx context.Context, p MaterializeParams, input dag_impl.Input) (Materialized, error) {
	if p.IsLocal {
		return materializeLocal(ctx, p)
	}
	return materializeRemote(ctx, p, input)
}

// RepoWorkPath is the working-tree location for a clone with the given directory
// name. Distinct RepoDirName values keep concurrent clones (HEAD vs published)
// from clobbering each other on disk.
func RepoWorkPath(ctx context.Context, input dag_impl.Input, repoDirName string) string {
	return filepath.Join(runpath.GetCloneCacheDir(ctx), input.BasePath(), repoDirName)
}

func materializeLocal(ctx context.Context, p MaterializeParams) (Materialized, error) {
	logger := ctxutil.GetLogger(ctx)

	logger.Debug("using local path", zap.String("path", p.SourceURL))

	// A local source's content is the files in the directory; git is not required
	// to read them (commit history is a separate concern resolved by git_resolve /
	// git_clone_metadata). Require only that the path is a readable directory so
	// file-based checks run on any local source, git or not.
	info, err := os.Stat(p.SourceURL)
	if err != nil {
		return materializedSkip(fmt.Sprintf("reading local source directory: %v", err)), nil
	}
	if !info.IsDir() {
		return materializedSkip(fmt.Sprintf("local source path is not a directory: %s", p.SourceURL)), nil
	}

	applyIgnorePatterns(ctx, p.SourceURL, p.Trusted)

	logger.Debug("prepared local source content", zap.String("path", p.SourceURL), zap.String("commit", p.CommitSHA))
	return materializedSuccess(p.SourceURL, p.CommitSHA), nil
}

func materializeRemote(ctx context.Context, p MaterializeParams, input dag_impl.Input) (Materialized, error) {
	logger := ctxutil.GetLogger(ctx)
	backend := cache.GetCacheBackend(ctx)

	useCache := !p.IsPrivate && p.CommitSHA != ""
	if useCache {
		m, hit, err := tryCloneCache(ctx, backend, p, input)
		if err != nil {
			return Materialized{}, err
		}
		if hit {
			return m, nil
		}
		logger.Debug("clone cache miss", zap.String("source_url", p.SourceURL), zap.String("commit", p.CommitSHA))
	}

	return cloneAndCache(ctx, backend, p, input, useCache)
}

func tryCloneCache(ctx context.Context, backend cache.Backend, p MaterializeParams, input dag_impl.Input) (Materialized, bool, error) {
	logger := ctxutil.GetLogger(ctx)

	tarPath, hit, err := git.GetCachedClone(ctx, backend, p.SparseCheckoutHash, p.NormalizedURL, p.CommitSHA)
	if err != nil {
		return Materialized{}, false, fmt.Errorf("checking clone cache: %w", err)
	}
	if !hit {
		return Materialized{}, false, nil
	}

	repoPath := RepoWorkPath(ctx, input, p.RepoDirName)
	if err := git.ExtractCachedRepo(tarPath, repoPath); err != nil {
		git.CleanupTarFile(tarPath)
		return Materialized{}, false, fmt.Errorf("extracting cached clone: %w", err)
	}
	git.CleanupTarFile(tarPath)

	applyIgnorePatterns(ctx, repoPath, p.Trusted)

	logger.Info("clone cache hit",
		zap.String("source_url", p.SourceURL),
		zap.String("commit", p.CommitSHA))

	return materializedSuccess(repoPath, p.CommitSHA), true, nil
}

func cloneAndCache(ctx context.Context, backend cache.Backend, p MaterializeParams, input dag_impl.Input, shouldCache bool) (Materialized, error) {
	logger := ctxutil.GetLogger(ctx)

	repoPath, err := executeCloneRemote(ctx, p, input)
	if err != nil {
		return Materialized{}, fmt.Errorf("clone failed after resolve succeeded: %w", err)
	}

	if repoPath == "" {
		return materializedSkip("unexpected: executeCloneRemote returned empty repoPath without error"), nil
	}

	if _, err := git.ValidateGitRepo(repoPath); err != nil {
		return materializedSkip(fmt.Sprintf("validating cloned git repository: %v", err)), nil
	}

	commit, err := git.GetHeadCommit(ctx, repoPath)
	if err != nil {
		return Materialized{}, fmt.Errorf("getting HEAD commit: %w", err)
	}

	gitDir := filepath.Join(repoPath, ".git")
	if err := os.RemoveAll(gitDir); err != nil {
		return Materialized{}, fmt.Errorf("removing .git directory: %w", err)
	}

	if shouldCache {
		if err := git.PutCachedClone(ctx, backend, p.SparseCheckoutHash, p.NormalizedURL, commit, repoPath); err != nil {
			return Materialized{}, fmt.Errorf("storing clone in cache: %w", err)
		}
	}

	applyIgnorePatterns(ctx, repoPath, p.Trusted)

	logger.Debug("cloned git repository", zap.String("path", repoPath), zap.String("commit", commit))
	return materializedSuccess(repoPath, commit), nil
}

func executeCloneRemote(ctx context.Context, p MaterializeParams, input dag_impl.Input) (string, error) {
	logger := ctxutil.GetLogger(ctx)
	repoPath := RepoWorkPath(ctx, input, p.RepoDirName)

	if err := os.MkdirAll(filepath.Dir(repoPath), 0o750); err != nil {
		return "", fmt.Errorf("creating source directory: %w", err)
	}

	logger.Debug("cloning repository", zap.String("source_url", p.SourceURL), zap.String("path", repoPath), zap.String("commit", p.CommitSHA))
	if err := git.CloneContentOnly(ctx, p.SourceURL, repoPath, p.CommitSHA, p.Patterns); err != nil {
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

func applyIgnorePatterns(ctx context.Context, repoPath string, trusted bool) {
	if !trusted {
		return
	}

	logger := ctxutil.GetLogger(ctx)
	if err := riskguardignore.ApplyIgnorePatterns(ctx, repoPath); err != nil {
		logger.Warn("failed to apply .riskguardignore", zap.Error(err))
	}
}

// BuildSparsePatterns returns the sparse-checkout patterns a content clone needs:
// license, generic, unsupported-manifest, and per-ecosystem file patterns.
func BuildSparsePatterns(ecosystems []def.Ecosystem) []string {
	result := make([]string, 0)
	result = append(result, licpatterns.GitSparseCheckoutPatterns()...)
	result = append(result, git.SparseCheckoutPatterns...)
	result = append(result, unsupported.SparseCheckoutPatterns...)

	for _, analyzer := range ecosystems {
		result = append(result, analyzer.GitSparseCheckoutFilePatterns()...)
	}

	return result
}

// HashPatterns returns a stable short hash of the sparse-checkout patterns, used
// as a component of the clone cache key so a pattern change invalidates it.
func HashPatterns(patterns []string) string {
	sorted := make([]string, len(patterns))
	copy(sorted, patterns)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return fmt.Sprintf("%x", h[:6])
}
