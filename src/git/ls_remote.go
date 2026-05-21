package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"risk-guard/src/common"
	"risk-guard/src/ctxutil"
	"strings"
	"time"
)

const lsRemoteTimeout = 10 * time.Second

// lsRemote runs `git ls-remote <url> <ref>` and returns the resolved SHA.
// For tags, if both a ref and its dereferenced form (^{}) are returned, the dereferenced SHA is used.
// Returns ("", nil) when the ref exists but has no output (e.g. empty repo HEAD).
func lsRemote(ctx context.Context, sourceURL, ref string) (string, error) {
	if err := common.ValidateRemoteURL(sourceURL); err != nil {
		return "", fmt.Errorf("validating URL: %w", err)
	}

	lsURL := sourceURL
	if token := ctxutil.GetSourceToken(ctx); token != "" {
		var err error
		lsURL, err = embedTokenInURL(sourceURL, token)
		if err != nil {
			return "", fmt.Errorf("embedding token: %w", err)
		}
	}

	lsCtx, cancel := context.WithTimeout(ctx, lsRemoteTimeout)
	defer cancel()

	//nolint:gosec // G204: URL is validated by ValidateRemoteURL, ref validated by caller
	cmd := exec.CommandContext(lsCtx, "git", "ls-remote", lsURL, ref)
	applySecureGitEnv(ctx, cmd)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	output, err := cmd.Output()
	if err != nil {
		rawErr := fmt.Errorf("git ls-remote: %s: %w", sanitizeGitOutput(stderrBuf.String()), err)
		return "", classifyCloneError(sourceURL, rawErr)
	}

	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return "", nil
	}

	// ls-remote may return multiple lines for tags (ref + ref^{}).
	// Prefer the dereferenced (^{}) line as it points to the commit SHA.
	var sha string
	for line := range strings.SplitSeq(trimmed, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		sha = parts[0]
		if strings.HasSuffix(parts[1], "^{}") {
			break
		}
	}

	if sha == "" {
		return "", fmt.Errorf("unexpected ls-remote output: %q", trimmed)
	}
	if len(sha) != 40 {
		return "", fmt.Errorf("invalid SHA from ls-remote: %q", sha)
	}

	return sha, nil
}

// GetRemoteHeadSHA returns the commit SHA that HEAD points to on the remote, without cloning.
// Returns ("", nil) for empty repos that have no HEAD ref.
func GetRemoteHeadSHA(ctx context.Context, sourceURL string) (string, error) {
	return lsRemote(ctx, sourceURL, "HEAD")
}

// GetRemoteRefSHA resolves an arbitrary git ref (branch, tag, commit prefix) to a full SHA via ls-remote.
func GetRemoteRefSHA(ctx context.Context, sourceURL, ref string) (string, error) {
	if err := ValidateGitRef(ref); err != nil {
		return "", fmt.Errorf("invalid git ref: %w", err)
	}

	sha, err := lsRemote(ctx, sourceURL, ref)
	if err != nil {
		return "", err
	}
	if sha == "" {
		return "", fmt.Errorf("ref %q not found on remote %s", ref, sourceURL)
	}
	return sha, nil
}
