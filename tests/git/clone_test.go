package git_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"testing"
)

func TestCloneRepository_PublicRepo(t *testing.T) {
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "repo")

	ctx := context.Background()
	cfg, _ := environment.Load()
	ctx = environment.SetConfig(ctx, cfg)

	err := git.CloneRepository(ctx, "https://github.com/octocat/Hello-World", repoPath, nil)
	if err != nil {
		t.Fatalf("CloneRepository failed: %v", err)
	}

	gitDir := filepath.Join(repoPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		t.Fatalf(".git directory not found after clone")
	}
}

func TestCloneRepository_InvalidURL(t *testing.T) {
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "repo")

	ctx := context.Background()
	cfg, _ := environment.Load()
	ctx = environment.SetConfig(ctx, cfg)

	err := git.CloneRepository(ctx, "https://github.com/nonexistent-user-xyz/nonexistent-repo-xyz", repoPath, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent repo, got nil")
	}

	var cloneErr *git.CloneError
	if !errors.As(err, &cloneErr) {
		t.Fatalf("expected CloneError, got %T: %v", err, err)
	}

	if cloneErr.Type != git.ErrTypeNotFound && cloneErr.Type != git.ErrTypePrivateRepo {
		t.Errorf("expected ErrTypeNotFound or ErrTypePrivateRepo, got %s", cloneErr.Type)
	}
}

func TestCloneRepository_UnsafeProtocol(t *testing.T) {
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "repo")

	ctx := context.Background()
	cfg, _ := environment.Load()
	ctx = environment.SetConfig(ctx, cfg)

	err := git.CloneRepository(ctx, "file:///etc/passwd", repoPath, nil)
	if err == nil {
		t.Fatal("expected error for file:// protocol, got nil")
	}

	var cloneErr *git.CloneError
	if !errors.As(err, &cloneErr) {
		t.Fatalf("expected CloneError, got %T: %v", err, err)
	}

	if cloneErr.Type != git.ErrTypeUnsafeProtocol {
		t.Errorf("expected ErrTypeUnsafeProtocol, got %s", cloneErr.Type)
	}
}

func TestCheckoutCommit_Tag(t *testing.T) {
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "repo")

	ctx := context.Background()
	cfg, _ := environment.Load()
	ctx = environment.SetConfig(ctx, cfg)

	// Clone expressjs/express (has many tags)
	err := git.CloneRepository(ctx, "https://github.com/expressjs/express", repoPath, nil)
	if err != nil {
		t.Fatalf("CloneRepository failed: %v", err)
	}

	// Checkout a known tag
	err = git.CheckoutCommit(ctx, repoPath, "4.18.0")
	if err != nil {
		t.Fatalf("CheckoutCommit failed: %v", err)
	}

	// Verify we're at the right commit
	//nolint:gosec // G204: repoPath is from t.TempDir(), safe in tests
	cmd := exec.Command("git", "-C", repoPath, "describe", "--tags", "--exact-match")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git describe failed: %v", err)
	}

	tag := string(output)
	if tag != "4.18.0\n" {
		t.Errorf("expected tag 4.18.0, got %q", tag)
	}
}

func TestCheckoutCommit_InvalidRef(t *testing.T) {
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "repo")

	ctx := context.Background()
	cfg, _ := environment.Load()
	ctx = environment.SetConfig(ctx, cfg)

	err := git.CloneRepository(ctx, "https://github.com/octocat/Hello-World", repoPath, nil)
	if err != nil {
		t.Fatalf("CloneRepository failed: %v", err)
	}

	err = git.CheckoutCommit(ctx, repoPath, "nonexistent-tag-xyz")
	if err == nil {
		t.Fatal("expected error for invalid ref, got nil")
	}
}

func TestCheckoutCommit_CommitSHA(t *testing.T) {
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "repo")

	ctx := context.Background()
	cfg, _ := environment.Load()
	ctx = environment.SetConfig(ctx, cfg)

	err := git.CloneRepository(ctx, "https://github.com/octocat/Hello-World", repoPath, nil)
	if err != nil {
		t.Fatalf("CloneRepository failed: %v", err)
	}

	// First commit in Hello-World repo
	err = git.CheckoutCommit(ctx, repoPath, "553c2077f0edc3d5dc5d17262f6aa498e69d6f8e")
	if err != nil {
		t.Fatalf("CheckoutCommit failed: %v", err)
	}

	// Verify HEAD
	//nolint:gosec // G204: repoPath is from t.TempDir(), safe in tests
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse failed: %v", err)
	}

	sha := string(output)
	if sha != "553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n" {
		t.Errorf("expected SHA 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e, got %q", sha)
	}
}

func TestValidateGitRef_Valid(t *testing.T) {
	validRefs := []string{
		"main",
		"v1.0.0",
		"4.18.0",
		"feature/my-branch",
		"553c2077f0edc3d5dc5d17262f6aa498e69d6f8e",
		"HEAD",
		"refs/tags/v1.0",
	}

	for _, ref := range validRefs {
		if err := git.ValidateGitRef(ref); err != nil {
			t.Errorf("ValidateGitRef(%q) returned error: %v", ref, err)
		}
	}
}

func TestValidateGitRef_Invalid(t *testing.T) {
	invalidRefs := []struct {
		ref    string
		reason string
	}{
		{"", "empty"},
		{"--version", "starts with dash (option injection)"},
		{"-n", "starts with dash"},
		{"main; rm -rf /", "shell metacharacter semicolon"},
		{"main | cat /etc/passwd", "shell metacharacter pipe"},
		{"$(whoami)", "command substitution"},
		{"main`id`", "backtick command substitution"},
		{"ref with spaces", "contains spaces"},
		{"ref\nwith\nnewlines", "contains newlines"},
		{"ref&background", "ampersand"},
	}

	for _, tc := range invalidRefs {
		if err := git.ValidateGitRef(tc.ref); err == nil {
			t.Errorf("ValidateGitRef(%q) should have failed (%s)", tc.ref, tc.reason)
		}
	}
}

func TestCheckoutCommit_InjectionAttempt(t *testing.T) {
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "repo")

	ctx := context.Background()
	cfg, _ := environment.Load()
	ctx = environment.SetConfig(ctx, cfg)

	err := git.CloneRepository(ctx, "https://github.com/octocat/Hello-World", repoPath, nil)
	if err != nil {
		t.Fatalf("CloneRepository failed: %v", err)
	}

	// Attempt option injection
	err = git.CheckoutCommit(ctx, repoPath, "--version")
	if err == nil {
		t.Fatal("CheckoutCommit should reject refs starting with dash")
	}

	// Attempt shell injection
	err = git.CheckoutCommit(ctx, repoPath, "main; rm -rf /")
	if err == nil {
		t.Fatal("CheckoutCommit should reject refs with shell metacharacters")
	}
}
