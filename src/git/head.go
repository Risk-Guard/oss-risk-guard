package git

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func GetHeadCommit(ctx context.Context, repoPath string) (string, error) {
	//nolint:gosec // G204: args are hardcoded git subcommands; repoPath is an internal trusted path
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "rev-parse", "HEAD")
	applySecureGitEnv(ctx, cmd)
	applyGitCeiling(cmd, repoPath)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("getting HEAD: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("getting HEAD: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
