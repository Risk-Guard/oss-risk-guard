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

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"

	"go.uber.org/zap"
)

const (
	// MaxCloneTime is the default per-clone timeout; CLONE_TIMEOUT_SECONDS
	// overrides it (see cloneTimeout).
	MaxCloneTime = 30 * time.Second
)

// cloneTimeout returns the configured per-clone timeout
// (CLONE_TIMEOUT_SECONDS), defaulting to MaxCloneTime.
func cloneTimeout(ctx context.Context) time.Duration {
	return environment.GetSharedConfig(ctx).GetCloneTimeout()
}

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

// applyGitEnv sets the environment for a git invocation. In secure-git mode it
// fully isolates git from local config and credentials. Otherwise it preserves
// the user's environment (PATH, HOME, credential helpers) but always disables
// interactive prompting, so an automated scan can never block on a credential
// or passphrase prompt: an inaccessible repo fails fast (and is recorded as
// skipped) instead of hanging the whole run.
func applyGitEnv(ctx context.Context, cmd *exec.Cmd) {
	logGitCommand(ctx, cmd)
	if environment.GetSharedConfig(ctx).GetSecureGit() {
		cmd.Env = isolatedGitEnv()
		return
	}
	cmd.Env = withNonInteractiveGit(cmd.Env)
}

// logGitCommand records the exact git invocation at debug level, so the run's
// debug log shows which git commands ran — and which one failed — even when the
// pretty-console error tree truncates git's own stderr.
func logGitCommand(ctx context.Context, cmd *exec.Cmd) {
	ctxutil.GetLogger(ctx).Debug("executing git command", zap.String("command", gitCommandString(cmd)))
}

// gitCommandString renders a git invocation for logs and error messages, with
// any credentials embedded in a clone URL stripped first so tokens never leak
// into output.
func gitCommandString(cmd *exec.Cmd) string {
	safe := make([]string, len(cmd.Args))
	for i, arg := range cmd.Args {
		if strings.Contains(arg, "://") && strings.Contains(arg, "@") {
			safe[i] = stripURLCredentials(arg)
		} else {
			safe[i] = arg
		}
	}
	return strings.Join(safe, " ")
}

// withNonInteractiveGit returns env with interactive git/ssh credential prompts
// disabled. Any existing values for these toggles are dropped so ours win;
// everything else (including credential helpers and SSH_AUTH_SOCK) is kept so
// non-interactive auth still works.
func withNonInteractiveGit(env []string) []string {
	if env == nil {
		env = os.Environ()
	}
	out := make([]string, 0, len(env)+4)
	for _, e := range env {
		switch {
		case strings.HasPrefix(e, "GIT_TERMINAL_PROMPT="),
			strings.HasPrefix(e, "GIT_ASKPASS="),
			strings.HasPrefix(e, "SSH_ASKPASS="),
			strings.HasPrefix(e, "GCM_INTERACTIVE="):
		default:
			out = append(out, e)
		}
	}
	return append(out,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"SSH_ASKPASS=",
		"GCM_INTERACTIVE=never",
	)
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
	filtered := cmd.Env[:0]
	for _, e := range cmd.Env {
		if !strings.HasPrefix(e, "GIT_CEILING_DIRECTORIES=") {
			filtered = append(filtered, e)
		}
	}
	cmd.Env = append(filtered, "GIT_CEILING_DIRECTORIES="+abs)
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
	initCmd := exec.CommandContext(ctx, "git", "-C", destDir, "sparse-checkout", "init", "--no-cone") //nolint:gosec // Args are hardcoded git subcommands
	applyGitEnv(ctx, initCmd)
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
