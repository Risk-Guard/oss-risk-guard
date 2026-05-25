package git

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/environment"
)

const (
	MaxCloneTime = 30 * time.Second
)

// isolatedGitEnv returns environment variables that isolate git from local config/credentials.
// This prevents git from using SSH keys, credential helpers, or user/system git configs.
func isolatedGitEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ASKPASS=false",
		"SSH_AUTH_SOCK=",
		"GIT_SSH_COMMAND=false",
		"HOME=/nonexistent",
	}
}

// applySecureGitEnv sets isolated env on cmd if secure git mode is enabled.
func applySecureGitEnv(ctx context.Context, cmd *exec.Cmd) {
	if environment.GetSharedConfig(ctx).GetSecureGit() {
		cmd.Env = isolatedGitEnv()
	}
}

// applyGitCeiling prevents git from walking above destDir when searching for
// a .git directory. Without this, `git -C destDir <subcmd>` will ascend
// parent directories if destDir lacks .git (e.g. because a parallel worker
// just removed it), and can mutate the first ancestor repo it finds —
// including the user's CWD repo. Apply this on every git invocation that
// targets destDir.
func applyGitCeiling(cmd *exec.Cmd, destDir string) {
	abs, err := filepath.Abs(destDir)
	if err != nil {
		abs = destDir
	}
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(cmd.Env, "GIT_CEILING_DIRECTORIES="+abs)
}

// SecurityPolicyPaths lists candidate locations for a security policy file.
// Used by the sparse checkout (to fetch these files) and the SOURCE_NO_SECURITY_POLICY check.
var SecurityPolicyPaths = []string{
	"SECURITY.md",
	"SECURITY.txt",
	"SECURITY.rst",
	".github/SECURITY.md",
	"docs/SECURITY.md",
}

// CIProvider defines the file paths and sparse checkout patterns for a CI service.
type CIProvider struct {
	Paths          []string // file/dir paths to check for existence
	SparsePatterns []string // sparse checkout globs; nil means same as Paths
}

// CIProviders is the single source of truth for all supported CI services.
// Key is the human-readable service name used in reporting.
var CIProviders = map[string]CIProvider{
	"GitHub Actions": {
		Paths:          []string{".github/workflows"},
		SparsePatterns: []string{".github/workflows/*.yml", ".github/workflows/*.yaml"},
	},
	"GitLab CI":           {Paths: []string{".gitlab-ci.yml", ".gitlab-ci.yaml"}},
	"CircleCI":            {Paths: []string{".circleci/config.yml", ".circleci/config.yaml"}},
	"Travis CI":           {Paths: []string{".travis.yml"}},
	"Jenkins":             {Paths: []string{"Jenkinsfile"}},
	"Azure Pipelines":     {Paths: []string{"azure-pipelines.yml"}},
	"Bitbucket Pipelines": {Paths: []string{"bitbucket-pipelines.yml"}},
	"AppVeyor":            {Paths: []string{"appveyor.yml"}},
}

func ciSparsePatterns() []string {
	var patterns []string
	for _, p := range CIProviders {
		if len(p.SparsePatterns) > 0 {
			patterns = append(patterns, p.SparsePatterns...)
		} else {
			patterns = append(patterns, p.Paths...)
		}
	}
	sort.Strings(patterns)
	return patterns
}

// SparseCheckoutPatterns collects all file patterns needed by source checks for sparse checkout.
var SparseCheckoutPatterns = append(append([]string{
	".risk-guard.yml",
	".riskguardignore",
}, SecurityPolicyPaths...), ciSparsePatterns()...)

const (
	ErrTypeNotFound         = "REPO_NOT_FOUND"
	ErrTypePrivateRepo      = "PRIVATE_REPO"
	ErrTypeTimeout          = "CLONE_TIMEOUT"
	ErrTypeUnsafeProtocol   = "UNSAFE_PROTOCOL"
	ErrTypeUnsupportedVCS   = "UNSUPPORTED_VCS"
	ErrTypeNetworkTransient = "NETWORK_TRANSIENT"
	ErrTypeOther            = "GIT_ERROR"
)

// embedTokenInURL embeds an auth token into a GitHub HTTPS URL.
// Uses the x-access-token username convention for GitHub token auth.
func embedTokenInURL(sourceURL, token string) (string, error) {
	parsed, err := url.Parse(sourceURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return sourceURL, nil
	}
	parsed.User = url.UserPassword("x-access-token", token)
	return parsed.String(), nil
}

func configureSparseCheckoutNative(ctx context.Context, destDir string, patterns []string) error {
	initCmd := exec.Command("git", "-C", destDir, "sparse-checkout", "init", "--no-cone") //nolint:gosec // Args are hardcoded git subcommands
	applySecureGitEnv(ctx, initCmd)
	applyGitCeiling(initCmd, destDir)
	if output, err := initCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to init sparse checkout: %w: %s", err, string(output))
	}

	sparseCheckoutPath := filepath.Join(destDir, ".git", "info", "sparse-checkout")
	patternsContent := strings.Join(patterns, "\n") + "\n"
	if err := os.WriteFile(sparseCheckoutPath, []byte(patternsContent), 0o600); err != nil {
		return fmt.Errorf("failed to write sparse-checkout file: %w", err)
	}

	return nil
}
