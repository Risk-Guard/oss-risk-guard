package git_clone_metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

const metadataCacheMaxAge = 365 * 24 * time.Hour

type Node struct {
	Description string `json:"description,omitempty"`
	isLocal     bool
	deps        []any
}

func NewNode(isLocal bool, deps []any) *Node {
	return &Node{
		Description: "Clones git repository metadata (commit history only, no file content) for analysis",
		isLocal:     isLocal,
		deps:        deps,
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	if !input.HasSourceURL() {
		return NewOutput(executiondag.StatusSkipped, "no source URL provided", input), nil
	}

	sourceURL := *input.SourceURL
	resolveOut := executiondag.GetOutput[*git_resolve.Node](ctx).(*git_resolve.Output)

	if n.isLocal {
		return n.handleLocal(ctx, sourceURL, resolveOut, input)
	}

	return n.handleRemote(ctx, sourceURL, resolveOut, input)
}

func (n *Node) handleLocal(ctx context.Context, sourceURL string, resolveOut *git_resolve.Output, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	repoPath, err := git.ValidateGitRepo(sourceURL)
	if err != nil {
		return NewOutput(
			executiondag.StatusSkipped,
			fmt.Sprintf("validating local git repository: %v", err),
			input,
		), nil
	}

	gitMeta, err := git.AnalyzeRepository(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("analyzing repository: %w", err)
	}

	logger.Debug("analyzed local git repository metadata",
		zap.String("path", repoPath),
		zap.String("commit", resolveOut.Commit))

	out := NewOutput(executiondag.StatusSuccess, "", input)
	out.GitMeta = gitMeta
	return out, nil
}

func (n *Node) handleRemote(ctx context.Context, sourceURL string, resolveOut *git_resolve.Output, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)
	backend := cache.GetCacheBackend(ctx)

	normalizedURL := resolveOut.NormalizedURL
	isPrivate := resolveOut.IsPrivate
	commitSHA := resolveOut.Commit

	useCache := !isPrivate && commitSHA != ""
	if useCache {
		out, err := n.tryMetadataCache(ctx, backend, normalizedURL, commitSHA, input)
		if err != nil {
			return nil, err
		}
		if out != nil {
			logger.Info("metadata cache hit",
				zap.String("source_url", sourceURL),
				zap.String("commit", commitSHA))
			return out, nil
		}
		logger.Debug("metadata cache miss",
			zap.String("source_url", sourceURL),
			zap.String("commit", commitSHA))
	}

	return n.cloneAndAnalyze(ctx, sourceURL, input, backend, normalizedURL, commitSHA, useCache)
}

func metadataCacheKey(normalizedURL, commitSHA string) string {
	urlHash := git.CacheKey(normalizedURL)
	return fmt.Sprintf("clone-cache/v3/metadata/%s/%s.json", urlHash, commitSHA)
}

func (n *Node) tryMetadataCache(ctx context.Context, backend cache.Backend, normalizedURL, commitSHA string, input dag_impl.Input) (*Output, error) {
	key := metadataCacheKey(normalizedURL, commitSHA)

	data, _, err := backend.Get(ctx, key, metadataCacheMaxAge)
	if err != nil {
		return nil, fmt.Errorf("checking metadata cache: %w", err)
	}
	if data == nil {
		return nil, nil
	}

	var meta models.GitMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("unmarshaling cached metadata: %w", err)
	}

	out := NewOutput(executiondag.StatusSuccess, "", input)
	out.GitMeta = &meta
	return out, nil
}

func (n *Node) cloneAndAnalyze(ctx context.Context, sourceURL string, input dag_impl.Input, backend cache.Backend, normalizedURL, commitSHA string, shouldCache bool) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)
	cloneCacheDir := runpath.GetCloneCacheDir(ctx)
	cloneDir := filepath.Join(cloneCacheDir, input.BasePath(), "metadata-repo")

	if err := os.MkdirAll(filepath.Dir(cloneDir), 0o750); err != nil {
		return nil, fmt.Errorf("creating directory: %w", err)
	}

	if err := git.CloneMetadataOnly(ctx, sourceURL, cloneDir); err != nil {
		return nil, fmt.Errorf("metadata clone failed after resolve succeeded: %w", err)
	}

	gitMeta, err := git.AnalyzeRepository(ctx, cloneDir)
	if err != nil {
		return nil, fmt.Errorf("analyzing repository: %w", err)
	}

	if err := os.RemoveAll(cloneDir); err != nil {
		return nil, fmt.Errorf("removing metadata clone dir: %w", err)
	}

	if shouldCache {
		if err := n.putMetadataCache(ctx, backend, normalizedURL, commitSHA, gitMeta); err != nil {
			return nil, fmt.Errorf("storing metadata in cache: %w", err)
		}
	}

	logger.Debug("cloned and analyzed git repository metadata",
		zap.String("source_url", sourceURL))

	out := NewOutput(executiondag.StatusSuccess, "", input)
	out.GitMeta = gitMeta
	return out, nil
}

func (n *Node) putMetadataCache(ctx context.Context, backend cache.Backend, normalizedURL, commitSHA string, meta *models.GitMetadata) error {
	key := metadataCacheKey(normalizedURL, commitSHA)

	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	if err := backend.Set(ctx, key, data); err != nil {
		return fmt.Errorf("storing metadata cache: %w", err)
	}

	return nil
}

func (n *Node) GetDependencies() []any {
	return n.deps
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, input)
}

func (n *Node) Kind() string {
	return "fetch"
}

func (n *Node) Read(ctx context.Context, input dag_impl.Input) (*Output, error) {
	if !input.HasSourceURL() {
		return NewOutput(
			executiondag.StatusSkipped,
			"no source URL provided",
			input,
		), nil
	}

	return dag_impl.ReadOutput[*Output](ctx, input)
}
