package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"

	"github.com/go-git/go-git/v5"
)

func CloneContentOnly(ctx context.Context, sourceURL, destDir, commitSHA string, sparseCheckoutPatterns []string) error {
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

	if _, err := os.Stat(destDir); err == nil {
		if _, err := git.PlainOpen(destDir); err == nil {
			return nil
		}
		if err := os.RemoveAll(destDir); err != nil {
			return fmt.Errorf("failed to remove existing directory: %w", err)
		}
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
	cloneCmd := exec.CommandContext(cloneCtx, "git", "clone",
		"--depth=1",
		"--single-branch",
		"--no-checkout",
		"--filter=blob:none",
		cloneURL,
		destDir,
	)
	applySecureGitEnv(ctx, cloneCmd)

	output, err := cloneCmd.CombinedOutput()
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

	if commitSHA != "" {
		if err := fetchAndCheckoutSHA(ctx, cloneCtx, sourceURL, destDir, commitSHA, sparseCheckoutPatterns); err != nil {
			return err
		}
	} else {
		if err := checkoutHEAD(ctx, cloneCtx, sourceURL, destDir, sparseCheckoutPatterns); err != nil {
			return err
		}
	}

	return nil
}

func fetchAndCheckoutSHA(ctx context.Context, cloneCtx context.Context, sourceURL, destDir, commitSHA string, sparseCheckoutPatterns []string) error {
	if err := configureSparseCheckoutNative(ctx, destDir, sparseCheckoutPatterns); err != nil {
		return cleanupAndReturn(destDir, fmt.Errorf("failed to configure sparse checkout: %w", err))
	}

	//nolint:gosec // G204: commitSHA is validated by IsFullSHA at call site
	fetchCmd := exec.CommandContext(cloneCtx, "git", "-C", destDir, "fetch", "--depth=1", "origin", commitSHA)
	applySecureGitEnv(ctx, fetchCmd)
	if output, err := fetchCmd.CombinedOutput(); err != nil {
		return cleanupAndReturn(destDir, classifyCloneError(sourceURL, fmt.Errorf("%w: %s", err, string(output))))
	}

	//nolint:gosec // G204: commitSHA is validated by IsFullSHA at call site
	checkoutCmd := exec.CommandContext(cloneCtx, "git", "-C", destDir, "checkout", commitSHA)
	applySecureGitEnv(ctx, checkoutCmd)
	if output, err := checkoutCmd.CombinedOutput(); err != nil {
		return cleanupAndReturn(destDir, classifyCloneError(sourceURL, fmt.Errorf("%w: %s", err, string(output))))
	}

	return nil
}

func checkoutHEAD(ctx context.Context, cloneCtx context.Context, sourceURL, destDir string, sparseCheckoutPatterns []string) error {
	if err := configureSparseCheckoutNative(ctx, destDir, sparseCheckoutPatterns); err != nil {
		return cleanupAndReturn(destDir, fmt.Errorf("failed to configure sparse checkout: %w", err))
	}

	checkoutCmd := exec.CommandContext(cloneCtx, "git", "-C", destDir, "checkout", "HEAD") //nolint:gosec // Args are hardcoded git subcommands
	applySecureGitEnv(ctx, checkoutCmd)
	if output, err := checkoutCmd.CombinedOutput(); err != nil {
		return cleanupAndReturn(destDir, classifyCloneError(sourceURL, fmt.Errorf("%w: %s", err, string(output))))
	}

	return nil
}

func cleanupAndReturn(destDir string, err error) error {
	if rmErr := os.RemoveAll(destDir); rmErr != nil {
		return fmt.Errorf("%w (cleanup error: %v)", err, rmErr)
	}
	return err
}
