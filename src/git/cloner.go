package git

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"risk-guard/src/common"
	"risk-guard/src/ctxutil"
	"risk-guard/src/environment"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
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

// CloneRepository clones a git repository with sparse checkout using the provided patterns.
// sparseCheckoutPatterns should include both language-specific dependency file patterns
// and license file patterns.
// If a source token is present in the context, it will be used for authentication.
func CloneRepository(ctx context.Context, sourceURL, destDir string, sparseCheckoutPatterns []string) error {
	// First layer: Validate URL meets security requirements (HTTPS-only, no localhost, etc.)
	if err := common.ValidateRemoteURL(sourceURL); err != nil {
		return &CloneError{
			URL:     sourceURL,
			Type:    ErrTypeUnsafeProtocol,
			Message: fmt.Sprintf("URL validation failed: %v", err),
		}
	}

	// Second layer: Defense-in-depth protocol check
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

	// Check if directory already exists and has a valid repo
	if _, err := os.Stat(destDir); err == nil {
		if _, err := git.PlainOpen(destDir); err == nil {
			return nil
		}
		if err := os.RemoveAll(destDir); err != nil {
			return fmt.Errorf("failed to remove existing directory: %w", err)
		}
	}

	// Embed token in URL if present in context
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
		"--single-branch",
		"--no-checkout",
		"--sparse",
		"--filter=tree:0",
		cloneURL,
		destDir,
	)
	applySecureGitEnv(ctx, cmd)

	output, err := cmd.CombinedOutput()
	if err != nil {
		rmErr := os.RemoveAll(destDir)

		// cloneCtx.Err() is the reliable timeout signal — exec.CommandContext
		// sends SIGKILL on deadline, but CombinedOutput returns an ExitError
		// ("signal: killed"), not context.DeadlineExceeded.
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

	if err := configureSparseCheckoutNative(ctx, destDir, sparseCheckoutPatterns); err != nil {

		if rmErr := os.RemoveAll(destDir); rmErr != nil {
			return fmt.Errorf("failed to configure sparse checkout: %w (cleanup error: %v)", err, rmErr)
		}
		return fmt.Errorf("failed to configure sparse checkout: %w", err)
	}

	checkoutCmd := exec.Command("git", "-C", destDir, "checkout", "HEAD") //nolint:gosec // Args are hardcoded git subcommands
	applySecureGitEnv(ctx, checkoutCmd)
	if output, err := checkoutCmd.CombinedOutput(); err != nil {
		if rmErr := os.RemoveAll(destDir); rmErr != nil {
			return classifyCloneError(sourceURL, fmt.Errorf("%w: %s (cleanup error: %v)", err, string(output), rmErr))
		}
		return classifyCloneError(sourceURL, fmt.Errorf("%w: %s", err, string(output)))
	}

	return nil
}

func configureSparseCheckoutNative(ctx context.Context, destDir string, patterns []string) error {
	initCmd := exec.Command("git", "-C", destDir, "sparse-checkout", "init", "--no-cone") //nolint:gosec // Args are hardcoded git subcommands
	applySecureGitEnv(ctx, initCmd)
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

// CheckoutCommit checks out a specific commit, branch, or tag in the repository.
// It first fetches tags to handle refs that weren't fetched with --single-branch.
func CheckoutCommit(ctx context.Context, repoPath, commit string) error {
	if err := ValidateGitRef(commit); err != nil {
		return fmt.Errorf("invalid commit ref: %w", err)
	}

	// Fetch tags (for tag-based commits like v4.18.0)
	fetchTagsCmd := exec.CommandContext(ctx, "git", "-C", repoPath, "fetch", "origin", "--tags") //nolint:gosec // Args are hardcoded git subcommands
	applySecureGitEnv(ctx, fetchTagsCmd)
	if output, err := fetchTagsCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to fetch tags: %w: %s", err, string(output))
	}

	//nolint:gosec // G204: commit validated by ValidateGitRef above
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "checkout", commit)
	applySecureGitEnv(ctx, cmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to checkout %s: %w: %s", commit, err, string(output))
	}
	return nil
}
