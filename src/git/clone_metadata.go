package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
)

// CloneMetadataOnly uses --filter=tree:0 --no-checkout to avoid downloading file content,
// reducing clone size for repos where only commit history is needed.
func CloneMetadataOnly(ctx context.Context, sourceURL, destDir string) error {
	if err := common.ValidateRemoteURL(sourceURL); err != nil {
		return &CloneError{
			URL:     sourceURL,
			Type:    ErrTypeUnsafeProtocol,
			Message: fmt.Sprintf("URL validation failed: %v", err),
		}
	}

	if !isValidProtocol(sourceURL) {
		return &CloneError{
			URL:     sourceURL,
			Type:    ErrTypeUnsafeProtocol,
			Message: "unsupported or unsafe protocol",
		}
	}

	cloneCtx, cancel := context.WithTimeout(ctx, MaxCloneTime)
	defer cancel()

	if err := os.MkdirAll(filepath.Dir(destDir), 0o750); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	if err := os.RemoveAll(destDir); err != nil {
		return fmt.Errorf("failed to remove existing directory: %w", err)
	}

	cloneURL := sourceURL
	if token := ctxutil.GetSourceToken(ctx); token != "" {
		var err error
		cloneURL, err = embedTokenInURL(sourceURL, token)
		if err != nil {
			return fmt.Errorf("failed to embed token in URL: %w", err)
		}
	}

	//nolint:gosec // G204: URL is validated by ValidateRemoteURL before use
	cmd := exec.CommandContext(cloneCtx, "git", "clone",
		"--filter=tree:0",
		"--single-branch",
		"--no-checkout",
		cloneURL,
		destDir,
	)
	applySecureGitEnv(ctx, cmd)
	applyGitCeiling(cmd, destDir)

	output, err := cmd.CombinedOutput()
	if err != nil {
		rmErr := os.RemoveAll(destDir)

		if cloneCtx.Err() == context.DeadlineExceeded {
			wrappedErr := err
			if rmErr != nil {
				wrappedErr = fmt.Errorf("%w (cleanup error: %v)", err, rmErr)
			}
			return &CloneError{
				URL:       sourceURL,
				Type:      ErrTypeTimeout,
				Message:   fmt.Sprintf("clone operation timed out after %v", MaxCloneTime),
				GitOutput: sanitizeGitOutput(extractGitErrorLine(string(output))),
				Err:       wrappedErr,
			}
		}

		if rmErr != nil {
			return classifyCloneError(sourceURL, fmt.Errorf("%w: %s (cleanup error: %v)", err, string(output), rmErr))
		}
		return classifyCloneError(sourceURL, fmt.Errorf("%w: %s", err, string(output)))
	}

	return nil
}
