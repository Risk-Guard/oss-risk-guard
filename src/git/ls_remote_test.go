package git

import (
	"context"
	"errors"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestGetRemoteHeadSHA_NotFound_ReturnsCloneError(t *testing.T) {
	ctx := context.Background()
	cfg := &environment.Config{SecureGit: true}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = ctxutil.SetLogger(ctx, zap.NewNop())

	_, err := GetRemoteHeadSHA(ctx, "https://github.com/nonexistent-owner-abc123/nonexistent-repo-xyz789")
	require.Error(t, err)

	var cloneErr *CloneError
	require.True(t, errors.As(err, &cloneErr), "expected *CloneError, got %T: %v", err, err)

	// GitHub returns 401 for nonexistent repos (to hide existence) when unauthenticated,
	// so the error type depends on auth context: REPO_NOT_FOUND or PRIVATE_REPO.
	// Both are correct permanent-failure classifications; the key invariant is NOT GIT_ERROR.
	require.Contains(t,
		[]string{ErrTypeNotFound, ErrTypePrivateRepo},
		cloneErr.Type,
		"expected REPO_NOT_FOUND or PRIVATE_REPO, got %s", cloneErr.Type,
	)
}

func TestGetRemoteRefSHA_Tag(t *testing.T) {
	ctx := context.Background()
	cfg := &environment.Config{SecureGit: true}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = ctxutil.SetLogger(ctx, zap.NewNop())

	sha, err := GetRemoteRefSHA(ctx, "https://github.com/expressjs/express", "v4.22.1")
	require.NoError(t, err)
	require.Len(t, sha, 40, "expected 40-char SHA, got %q", sha)
}

func TestGetRemoteRefSHA_NotFound(t *testing.T) {
	ctx := context.Background()
	cfg := &environment.Config{SecureGit: true}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = ctxutil.SetLogger(ctx, zap.NewNop())

	_, err := GetRemoteRefSHA(ctx, "https://github.com/expressjs/express", "v999.999.999-nonexistent")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}
