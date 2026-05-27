package git_resolve

import (
	"context"
	"errors"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/git"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type Node struct {
	Description string `json:"description,omitempty"`
	isLocal     bool
	deps        []any
}

func NewNode(isLocal bool, deps []any) *Node {
	return &Node{
		Description: "Resolves git repository: validates access, determines commit SHA, and classifies errors",
		isLocal:     isLocal,
		deps:        deps,
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	if !input.HasSourceURL() {
		return NewOutput(
			executiondag.StatusSkipped,
			"no source URL provided",
			input,
		), nil
	}

	sourceURL := *input.SourceURL
	logger := ctxutil.GetLogger(ctx)

	logger.Debug("resolving git repository", zap.String("source_url", sourceURL))

	if n.isLocal {
		return n.handleLocalResolve(ctx, sourceURL, input)
	}

	return n.handleRemoteResolve(ctx, sourceURL, input)
}

func (n *Node) handleLocalResolve(ctx context.Context, sourceURL string, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	repoPath, err := git.ValidateGitRepo(sourceURL)
	if err != nil {
		return NewOutput(
			executiondag.StatusSkipped,
			fmt.Sprintf("validating local git repository: %v", err),
			input,
		), nil
	}

	commit, err := git.GetHeadCommit(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("getting HEAD commit: %w", err)
	}

	logger.Debug("resolved local git repository",
		zap.String("path", repoPath),
		zap.String("commit", commit))

	out := NewOutput(executiondag.StatusSuccess, "", input)
	out.Commit = commit
	return out, nil
}

func (n *Node) handleRemoteResolve(ctx context.Context, sourceURL string, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	normalizedURL, err := git.NormalizeCacheURL(sourceURL)
	if err != nil {
		return nil, fmt.Errorf("normalizing cache URL: %w", err)
	}

	isPrivate, err := git.IsPrivateRequest(ctx, sourceURL)
	if err != nil {
		return nil, fmt.Errorf("checking private request: %w", err)
	}

	commitSHA, err := resolveCommitSHA(ctx, sourceURL, input)
	if err != nil {
		return n.handleResolveError(ctx, err, input)
	}

	logger.Debug("resolved git repository",
		zap.String("source_url", sourceURL),
		zap.String("commit", commitSHA),
		zap.Bool("is_private", isPrivate))

	out := NewOutput(executiondag.StatusSuccess, "", input)
	out.Commit = commitSHA
	out.NormalizedURL = normalizedURL
	out.IsPrivate = isPrivate
	return out, nil
}

func resolveCommitSHA(ctx context.Context, sourceURL string, input dag_impl.Input) (string, error) {
	if input.Commit != nil && git.IsFullSHA(*input.Commit) {
		return *input.Commit, nil
	}

	sha, err := git.GetRemoteHeadSHA(ctx, sourceURL)
	if err != nil {
		return "", err
	}

	if input.Commit != nil && *input.Commit != "" {
		return git.GetRemoteRefSHA(ctx, sourceURL, *input.Commit)
	}

	return sha, nil
}

func (n *Node) handleResolveError(ctx context.Context, err error, input dag_impl.Input) (*Output, error) {
	var cloneErr *git.CloneError
	if !errors.As(err, &cloneErr) {
		return nil, err
	}

	gitErrDetails := &GitErrorDetails{
		Type:      cloneErr.Type,
		Message:   cloneErr.Message,
		GitOutput: cloneErr.GitOutput,
	}

	switch cloneErr.Type {
	case git.ErrTypeTimeout, git.ErrTypeUnsafeProtocol, git.ErrTypeNetworkTransient:
		return nil, err
	case git.ErrTypePrivateRepo:
		if ctxutil.GetSourceToken(ctx) != "" {
			return nil, fmt.Errorf("authentication failed with provided token: %s", cloneErr.Message)
		}
		out := NewOutputWithError(
			executiondag.StatusSkipped,
			fmt.Sprintf("private repository (authentication required): %s", cloneErr.Message),
			gitErrDetails,
			input,
		)
		return out, nil
	default:
		out := NewOutputWithError(
			executiondag.StatusSkipped,
			cloneErr.Message,
			gitErrDetails,
			input,
		)
		out.UnsupportedVCS = cloneErr.Type == git.ErrTypeUnsupportedVCS
		return out, nil
	}
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
