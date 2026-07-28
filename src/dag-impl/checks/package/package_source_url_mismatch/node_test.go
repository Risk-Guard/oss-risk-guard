package package_source_url_mismatch

import (
	"context"
	"os/exec"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"

	"go.uber.org/zap"
)

func testCtx() context.Context {
	ctx := environment.SetSharedConfig(context.Background(), &environment.Config{})
	return ctxutil.SetLogger(ctx, zap.NewNop())
}

// initRepo creates a git repo in a fresh temp dir, optionally adding an origin
// remote. An empty template dir keeps the sandbox from blocking hook copies.
func initRepo(t *testing.T, originURL string) string {
	t.Helper()
	dir := t.TempDir()
	tmplDir := t.TempDir()
	if err := exec.Command("git", "init", "-q", "--template="+tmplDir, dir).Run(); err != nil {
		t.Fatalf("git init: %v", err)
	}
	if originURL != "" {
		if err := exec.Command("git", "-C", dir, "remote", "add", "origin", originURL).Run(); err != nil {
			t.Fatalf("git remote add: %v", err)
		}
	}
	return dir
}

// A remote scan already provides a repository URL; it must pass through
// unchanged and be usable for comparison.
func TestResolveComparisonURL_RemoteURLPassthrough(t *testing.T) {
	got, ok := resolveComparisonURL(testCtx(), "https://github.com/pytorch/pytorch")
	if !ok {
		t.Fatal("expected ok=true for a remote URL")
	}
	if got != "https://github.com/pytorch/pytorch" {
		t.Errorf("expected passthrough URL, got %q", got)
	}
}

// A local checkout resolves to the canonical URL of its git origin remote, so a
// registry source URL can be compared URL-against-URL instead of against the
// filesystem path. This is the pytorch false-positive case.
func TestResolveComparisonURL_LocalHTTPSOrigin(t *testing.T) {
	dir := initRepo(t, "https://github.com/pytorch/pytorch.git")

	got, ok := resolveComparisonURL(testCtx(), dir)
	if !ok {
		t.Fatal("expected ok=true for a local repo with an origin remote")
	}
	if got != "https://github.com/pytorch/pytorch" {
		t.Errorf("expected canonical origin URL, got %q", got)
	}
	if !normalizeAndCompareURLs(got, "https://github.com/pytorch/pytorch") {
		t.Errorf("resolved origin %q should match the registry source URL", got)
	}
}

// SCP-style SSH remotes (git@github.com:owner/repo.git) must also normalize to
// the canonical https identity.
func TestResolveComparisonURL_LocalSCPOrigin(t *testing.T) {
	dir := initRepo(t, "git@github.com:pytorch/pytorch.git")

	got, ok := resolveComparisonURL(testCtx(), dir)
	if !ok {
		t.Fatal("expected ok=true for a local repo with an SCP-style origin")
	}
	if got != "https://github.com/pytorch/pytorch" {
		t.Errorf("expected canonical origin URL from SCP remote, got %q", got)
	}
}

// A local repo with no origin remote has no canonical identity, so the check
// must be skipped (ok=false) rather than compared against the filesystem path.
func TestResolveComparisonURL_LocalNoOrigin(t *testing.T) {
	dir := initRepo(t, "")

	if _, ok := resolveComparisonURL(testCtx(), dir); ok {
		t.Error("expected ok=false for a local repo without an origin remote")
	}
}

// A local path that is not a git repo at all likewise yields no identity.
func TestResolveComparisonURL_LocalNonGitDir(t *testing.T) {
	dir := t.TempDir()

	if _, ok := resolveComparisonURL(testCtx(), dir); ok {
		t.Error("expected ok=false for a non-git local directory")
	}
}
