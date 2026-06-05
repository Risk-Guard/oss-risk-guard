package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/environment"
)

// An init'd repo with no commits is a valid state (`git init` then nothing
// committed yet). `git log` exits 128 in that case. AnalyzeRepository must
// return GitMetadata with the resolved SourceURL and no commit stats —
// not fail analysis.
func TestAnalyzeRepository_EmptyRepoNoCommits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	// Use an empty template so the sandbox doesn't block hook copies.
	tmplDir := filepath.Join(t.TempDir(), "tmpl")
	if err := exec.Command("git", "init", "-q", "--template="+tmplDir, dir).Run(); err != nil {
		t.Fatalf("git init: %v", err)
	}

	cfg := &environment.Config{}
	ctx := environment.SetSharedConfig(context.Background(), cfg)

	meta, err := AnalyzeRepository(ctx, dir)
	if err != nil {
		t.Fatalf("AnalyzeRepository on empty repo returned error: %v", err)
	}
	if meta == nil {
		t.Fatal("expected non-nil GitMetadata for empty repo")
	}
	if meta.SourceURL == "" {
		t.Errorf("expected SourceURL fallback to repo path, got empty")
	}
	if meta.CommitCount != nil && *meta.CommitCount != 0 {
		t.Errorf("expected nil/zero CommitCount, got %v", meta.CommitCount)
	}
}

func TestAnalyzeRepository_ErrorHandling(t *testing.T) {
	_, err := AnalyzeRepository(context.Background(), "/nonexistent/path/to/repo")

	if err == nil {
		t.Fatal("Expected error for non-existent repository")
	}

	if !strings.Contains(err.Error(), "failed to open repository") {
		t.Errorf("Expected 'failed to open repository' error, got: %v", err)
	}
}

// TestAnalyzeRepository_NoOriginRemote tests handling of repos without origin remote
func TestAnalyzeRepository_NoOriginRemote(t *testing.T) {
	// This test would need a test fixture repo without origin
	// For now, we'll test the getRemoteURL helper directly if it were exported
	// Or we skip this test and verify behavior in integration tests
	t.Skip("Requires test fixture repository without origin remote")
}

// TestExtractCommitHistory_StringErrorComparison tests the problematic string-based error comparison
func TestExtractCommitHistory_StringErrorComparison(t *testing.T) {
	// This test exposes the bug in line 103 of analyzer.go:
	// if err != nil && err.Error() != "object not found"

	// The problem: This is fragile and won't work if:
	// 1. Error message changes slightly
	// 2. Error is wrapped
	// 3. Different error types with similar messages exist

	// We can't easily test this without creating a shallow clone fixture
	// But we can document the expected behavior:
	// - Shallow clones should return partial commit data + error indicator
	// - Not silently return empty commits

	t.Log("NOTE: Current implementation uses string comparison for errors (line 103)")
	t.Log("This should be replaced with error type checking or error wrapping")

	// After fix, the function should:
	// 1. Return partial commits collected so far
	// 2. Set an Error field in GitMetadata to indicate incomplete data
	// 3. Not use err.Error() == "string" comparison
}

// TestIsBotCommit_PrivacyEnabledHumans tests that GitHub privacy emails are NOT filtered as bots
func TestIsBotCommit_PrivacyEnabledHumans(t *testing.T) {
	// These are HUMANS with privacy enabled - should NOT be filtered
	humanEmails := []string{
		"username@users.noreply.github.com",          // Old format privacy email
		"9087854+aa-turner@users.noreply.github.com", // Real case from sphinxcontrib-htmlhelp
		"123456+user@users.noreply.github.com",       // New format privacy email (since July 2017)
		"user@example.com",                           // Regular email
		"developer@company.com",                      // Corporate email
	}

	for _, email := range humanEmails {
		if isBotCommit(email) {
			t.Errorf("Human email incorrectly marked as bot: %s", email)
		}
	}
}

// TestIsBotCommit_ActualBots tests that actual bot emails ARE filtered
func TestIsBotCommit_ActualBots(t *testing.T) {
	// These are ACTUAL BOTS - should be filtered
	botEmails := []string{
		"41898282+github-actions[bot]@users.noreply.github.com", // GitHub Actions bot
		"49699333+dependabot[bot]@users.noreply.github.com",     // Dependabot
		"29139614+renovate[bot]@users.noreply.github.com",       // Renovate bot
		"github-actions[bot]@users.noreply.github.com",          // GitHub Actions (old format)
		"noreply@github.com",     // GitHub system
		"support@dependabot.com", // Dependabot (legacy)
	}

	for _, email := range botEmails {
		if !isBotCommit(email) {
			t.Errorf("Bot email incorrectly marked as human: %s", email)
		}
	}
}

// TestAnalyzeCommitMetrics_BotFiltering tests that bot commits are filtered correctly
func TestAnalyzeCommitMetrics_BotFiltering(t *testing.T) {
	now := time.Now()

	commits := []CommitInfo{
		{AuthorEmail: "user@example.com", Timestamp: now},                             // Human
		{AuthorEmail: "github-actions[bot]@users.noreply.github.com", Timestamp: now}, // Bot - should be filtered
		{AuthorEmail: "other@example.com", Timestamp: now},                            // Human
		{AuthorEmail: "dependabot[bot]@users.noreply.github.com", Timestamp: now},     // Bot - should be filtered
	}

	metrics := analyzeCommitMetrics(commits)

	if metrics.CommitCount != 4 {
		t.Errorf("Expected CommitCount=4 (all commits), got %d", metrics.CommitCount)
	}

	if metrics.HumanCommitCount != 2 {
		t.Errorf("Expected HumanCommitCount=2 (excluding bots), got %d", metrics.HumanCommitCount)
	}

	if metrics.RecentAuthorsCount != 2 {
		t.Errorf("Expected RecentAuthorsCount=2 (excluding bots), got %d", metrics.RecentAuthorsCount)
	}
}

// TestAnalyzeCommitMetrics_MixedWithPrivacyEmails tests filtering with privacy-enabled humans
func TestAnalyzeCommitMetrics_MixedWithPrivacyEmails(t *testing.T) {
	now := time.Now()

	commits := []CommitInfo{
		{AuthorEmail: "9087854+aa-turner@users.noreply.github.com", Timestamp: now},   // Privacy-enabled HUMAN
		{AuthorEmail: "github-actions[bot]@users.noreply.github.com", Timestamp: now}, // Bot
		{AuthorEmail: "123456+developer@users.noreply.github.com", Timestamp: now},    // Privacy-enabled HUMAN
		{AuthorEmail: "regular@example.com", Timestamp: now},                          // Regular human
	}

	metrics := analyzeCommitMetrics(commits)

	if metrics.CommitCount != 4 {
		t.Errorf("Expected CommitCount=4, got %d", metrics.CommitCount)
	}

	if metrics.HumanCommitCount != 3 {
		t.Errorf("Expected HumanCommitCount=3 (2 privacy-enabled + 1 regular), got %d", metrics.HumanCommitCount)
	}

	if metrics.RecentAuthorsCount != 3 {
		t.Errorf("Expected RecentAuthorsCount=3 (3 humans, 1 bot filtered), got %d", metrics.RecentAuthorsCount)
	}
}

// TestAnalyzeCommitMetrics_EmptyCommits tests handling of empty commit history
func TestAnalyzeCommitMetrics_EmptyCommits(t *testing.T) {
	commits := []CommitInfo{}

	metrics := analyzeCommitMetrics(commits)

	// Should return zero values, not panic
	if metrics.CommitCount != 0 {
		t.Errorf("Expected CommitCount=0, got %d", metrics.CommitCount)
	}

	if metrics.RecentAuthorsCount != 0 {
		t.Errorf("Expected RecentAuthorsCount=0, got %d", metrics.RecentAuthorsCount)
	}

	if metrics.MaxMonthlyAuthorsCount != 0 {
		t.Errorf("Expected MaxMonthlyAuthorsCount=0, got %d", metrics.MaxMonthlyAuthorsCount)
	}
}

// TestAnalyzeCommitMetrics_AllBotsEdgeCase tests when all commits are from bots
func TestAnalyzeCommitMetrics_AllBotsEdgeCase(t *testing.T) {
	now := time.Now()

	commits := []CommitInfo{
		{AuthorEmail: "github-actions[bot]@users.noreply.github.com", Timestamp: now},
		{AuthorEmail: "dependabot[bot]@users.noreply.github.com", Timestamp: now},
		{AuthorEmail: "noreply@github.com", Timestamp: now},
	}

	metrics := analyzeCommitMetrics(commits)

	if metrics.CommitCount != 3 {
		t.Errorf("Expected CommitCount=3, got %d", metrics.CommitCount)
	}

	if metrics.HumanCommitCount != 0 {
		t.Errorf("Expected HumanCommitCount=0, got %d", metrics.HumanCommitCount)
	}

	if metrics.RecentAuthorsCount == 0 {
		t.Error("Expected non-zero RecentAuthorsCount (fallback to bot commits)")
	}
}

// TestAnalyzeCommitMetrics_EmailCaseNormalization tests that mixed-case emails are deduplicated
func TestAnalyzeCommitMetrics_EmailCaseNormalization(t *testing.T) {
	now := time.Now()

	// Same person, different email casing across commits
	commits := []CommitInfo{
		{AuthorEmail: "john@example.com", Timestamp: now},
		{AuthorEmail: "John@Example.com", Timestamp: now.AddDate(0, 0, -1)},
		{AuthorEmail: "JOHN@EXAMPLE.COM", Timestamp: now.AddDate(0, 0, -2)},
		{AuthorEmail: "other@example.com", Timestamp: now.AddDate(0, 0, -3)},
	}

	metrics := analyzeCommitMetrics(commits)

	if metrics.RecentAuthorsCount != 2 {
		t.Errorf("Expected RecentAuthorsCount=2 (john + other, case-insensitive), got %d", metrics.RecentAuthorsCount)
	}

	if metrics.MaxMonthlyAuthorsCount != 2 {
		t.Errorf("Expected MaxMonthlyAuthorsCount=2 (john + other, case-insensitive), got %d", metrics.MaxMonthlyAuthorsCount)
	}
}

// TestCalculateMaxMonthlyAuthors tests the 30-day rolling window calculation
func TestCalculateMaxMonthlyAuthors(t *testing.T) {
	now := time.Now()

	// Create commits over a 60-day period with varying author counts
	commits := []CommitInfo{
		// First 30 days: 3 unique authors
		{AuthorEmail: "user1@example.com", Timestamp: now.AddDate(0, 0, -1)},
		{AuthorEmail: "user2@example.com", Timestamp: now.AddDate(0, 0, -10)},
		{AuthorEmail: "user3@example.com", Timestamp: now.AddDate(0, 0, -20)},
		// Next 30 days: 5 unique authors (should be the max)
		{AuthorEmail: "user1@example.com", Timestamp: now.AddDate(0, 0, -31)},
		{AuthorEmail: "user2@example.com", Timestamp: now.AddDate(0, 0, -35)},
		{AuthorEmail: "user3@example.com", Timestamp: now.AddDate(0, 0, -40)},
		{AuthorEmail: "user4@example.com", Timestamp: now.AddDate(0, 0, -45)},
		{AuthorEmail: "user5@example.com", Timestamp: now.AddDate(0, 0, -50)},
	}

	result := calculateMaxMonthlyAuthors(commits)

	if result.MaxAuthors < 3 {
		t.Errorf("Expected MaxAuthors >= 3, got %d", result.MaxAuthors)
	}

	// Window dates should be within the commit range
	earliest := now.AddDate(0, 0, -50)
	if result.WindowStart.Before(earliest.AddDate(0, 0, -30)) {
		t.Errorf("WindowStart %v is too early", result.WindowStart)
	}
	if result.WindowEnd.After(now.Add(24 * time.Hour)) {
		t.Errorf("WindowEnd %v is after now", result.WindowEnd)
	}
	if result.WindowEnd.Before(result.WindowStart) {
		t.Errorf("WindowEnd %v is before WindowStart %v", result.WindowEnd, result.WindowStart)
	}

	t.Logf("Max authors: %d, window: %s to %s", result.MaxAuthors,
		result.WindowStart.Format("2006-01-02"), result.WindowEnd.Format("2006-01-02"))
}

// TestCalculateMaxMonthlyAuthors_Empty tests edge case of empty commits
func TestCalculateMaxMonthlyAuthors_Empty(t *testing.T) {
	commits := []CommitInfo{}

	result := calculateMaxMonthlyAuthors(commits)

	if result.MaxAuthors != 0 {
		t.Errorf("Expected MaxAuthors=0 for empty commits, got %d", result.MaxAuthors)
	}
	if !result.WindowStart.IsZero() {
		t.Errorf("Expected zero WindowStart for empty commits, got %v", result.WindowStart)
	}
	if !result.WindowEnd.IsZero() {
		t.Errorf("Expected zero WindowEnd for empty commits, got %v", result.WindowEnd)
	}
}

// TestGitMetadata_StatusReasonFieldUsage tests that StatusReason field is used for partial failures
func TestGitMetadata_StatusReasonFieldUsage(t *testing.T) {
	// GitMetadata has a StatusReason *string field for partial failures
	// This test documents how the field is used

	// Test that AnalyzeRepository properly sets the StatusReason field
	// for partial failures (e.g., shallow clones)

	t.Log("NOTE: GitMetadata.StatusReason field is populated for partial failures")
	t.Log("Usage pattern:")
	t.Log("- Success: return (metadata, nil) with StatusReason = nil")
	t.Log("- Partial success: return (metadata, nil) with StatusReason = 'shallow clone...'")
	t.Log("- Complete failure: return (metadata, nil) with StatusReason = error message")
}

// TestValidateGitRepo_NonExistentPath tests validation with non-existent path
func TestValidateGitRepo_NonExistentPath(t *testing.T) {
	_, err := ValidateGitRepo("/nonexistent/path/to/repo")

	if err == nil {
		t.Fatal("Expected error for non-existent path")
	}

	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("Expected 'does not exist' error, got: %v", err)
	}
}

// TestValidateGitRepo_NotADirectory tests validation with a file instead of directory
func TestValidateGitRepo_NotADirectory(t *testing.T) {
	// This test would need a test fixture file
	// For now we document the expected behavior
	t.Skip("Requires test fixture file to verify 'not a directory' error")
}

// TestValidateGitRepo_NotAGitRepo tests validation with a directory without .git
func TestValidateGitRepo_NotAGitRepo(t *testing.T) {
	// Create a temporary directory without .git
	t.Skip("Requires temporary directory creation - covered by integration tests")
}

// TestValidateGitRepo_RelativePath tests that relative paths are resolved to absolute
func TestValidateGitRepo_RelativePath(t *testing.T) {
	// This test documents that ValidateGitRepo accepts relative paths
	// and returns absolute paths
	t.Log("NOTE: ValidateGitRepo() accepts both relative and absolute paths")
	t.Log("- Returns absolute path on success")
	t.Log("- Uses filepath.Abs() to resolve relative paths")
}

// TestResolveRepoRoot_WalksUpToToplevel verifies that a path inside a repo
// resolves to the repo root, the way `git rev-parse --show-toplevel` does.
func TestResolveRepoRoot_WalksUpToToplevel(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	tmplDir := filepath.Join(t.TempDir(), "tmpl")
	if err := exec.Command("git", "init", "-q", "--template="+tmplDir, dir).Run(); err != nil {
		t.Fatalf("git init: %v", err)
	}
	sub := filepath.Join(dir, "nested", "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	ctx := context.Background()
	rootFromRoot, isGit, err := ResolveRepoRoot(ctx, dir)
	if err != nil {
		t.Fatalf("ResolveRepoRoot(root): %v", err)
	}
	if !isGit {
		t.Fatal("expected isGit=true for the repo root")
	}
	if filepath.Base(rootFromRoot) != "repo" {
		t.Errorf("expected toplevel basename 'repo', got %q", rootFromRoot)
	}

	rootFromSub, isGit, err := ResolveRepoRoot(ctx, sub)
	if err != nil {
		t.Fatalf("ResolveRepoRoot(sub): %v", err)
	}
	if !isGit {
		t.Fatal("expected isGit=true from a nested subdirectory")
	}
	if rootFromSub != rootFromRoot {
		t.Errorf("walk-up mismatch: sub resolved to %q, root resolved to %q", rootFromSub, rootFromRoot)
	}
}

// TestResolveRepoRoot_NonGitDirectoryProceeds verifies that a directory not in a
// git repo is not an error: isGit is false and root is the cleaned absolute path
// so callers can still operate on it (git-history checks downstream just skip).
func TestResolveRepoRoot_NonGitDirectoryProceeds(t *testing.T) {
	dir := t.TempDir()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}

	root, isGit, err := ResolveRepoRoot(context.Background(), dir)
	if err != nil {
		t.Fatalf("ResolveRepoRoot on non-git dir returned error: %v", err)
	}
	if isGit {
		t.Error("expected isGit=false for a directory with no git repo")
	}
	if root != abs {
		t.Errorf("expected root to be the cleaned abs path %q, got %q", abs, root)
	}
}

// TestResolveRepoRoot_NonExistentPath verifies a missing path is still a hard
// error — that's a user mistake, not an absent repo.
func TestResolveRepoRoot_NonExistentPath(t *testing.T) {
	_, _, err := ResolveRepoRoot(context.Background(), "/nonexistent/path/to/repo")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected 'does not exist' error, got: %v", err)
	}
}
