package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

func ValidateGitRepo(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path does not exist: %s", absPath)
		}
		return "", fmt.Errorf("failed to access path: %w", err)
	}

	if !info.IsDir() {
		return "", fmt.Errorf("path is not a directory: %s", absPath)
	}

	gitDir := filepath.Join(absPath, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("not a git repository (no .git directory): %s", absPath)
		}
		return "", fmt.Errorf("failed to check .git directory: %w", err)
	}

	return absPath, nil
}

// ResolveRepoRoot resolves path to the root of its git work tree using
// `git rev-parse --show-toplevel`, which walks up parent directories the same
// way git itself does (and handles worktrees/submodules where .git is a file).
// isGit is false when path is not inside a git repo, or git is unavailable; in
// that case root is the cleaned absolute path so callers can still operate on
// the directory — the source DAG auto-skips git-history checks for non-git
// paths. A missing path or non-directory is a hard error regardless, since that
// is a user mistake rather than an absent repo.
func ResolveRepoRoot(ctx context.Context, path string) (root string, isGit bool, err error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, fmt.Errorf("path does not exist: %s", absPath)
		}
		return "", false, fmt.Errorf("failed to access path: %w", err)
	}
	if !info.IsDir() {
		return "", false, fmt.Errorf("path is not a directory: %s", absPath)
	}

	// rev-parse --show-toplevel is a local-only metadata read — it never
	// contacts a remote and so never prompts. Keep it free of the shared-config
	// dependency that applyGitEnv carries, so ResolveRepoRoot works in any ctx.
	//nolint:gosec // G204: args are hardcoded git subcommands; absPath is a validated local directory
	out, err := exec.CommandContext(ctx, "git", "-C", absPath, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return absPath, false, nil
	}
	top := strings.TrimSpace(string(out))
	if top == "" {
		return absPath, false, nil
	}
	return top, true, nil
}

func AnalyzeRepository(ctx context.Context, repoPath string) (*models.GitMetadata, error) {
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	sourceURL, found, err := getRemoteURL(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read git remotes: %w", err)
	}
	if !found {
		absPath, err := filepath.Abs(repoPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
		}
		sourceURL = absPath
	}

	commits, err := extractCommitHistory(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read commit history: %w", err)
	}

	if len(commits) == 0 {
		return &models.GitMetadata{SourceURL: sourceURL}, nil
	}

	metrics := analyzeCommitMetrics(commits)

	metadata := &models.GitMetadata{
		SourceURL:              sourceURL,
		RecentAuthorsCount:     &metrics.RecentAuthorsCount,
		MaxMonthlyAuthorsCount: &metrics.MaxMonthlyAuthorsCount,
		FirstCommit:            &metrics.FirstCommit,
		LatestHumanCommit:      &metrics.LatestHumanCommit,
		CommitCount:            &metrics.CommitCount,
		HumanCommitCount:       &metrics.HumanCommitCount,
	}
	if !metrics.MaxMonthlyWindowStart.IsZero() && !metrics.MaxMonthlyWindowEnd.IsZero() {
		metadata.MaxMonthlyWindowStart = &metrics.MaxMonthlyWindowStart
		metadata.MaxMonthlyWindowEnd = &metrics.MaxMonthlyWindowEnd
	}
	return metadata, nil
}

func getRemoteURL(ctx context.Context, repoPath string) (string, bool, error) {
	//nolint:gosec // G204: args are hardcoded git subcommands; repoPath is an internal trusted path
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "config", "--get", "remote.origin.url")
	applyGitEnv(ctx, cmd)
	applyGitCeiling(cmd, repoPath)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 1 {
				return "", false, nil
			}
			if len(exitErr.Stderr) > 0 {
				return "", false, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
			}
		}
		return "", false, err
	}
	url := strings.TrimSpace(string(out))
	if url == "" {
		return "", false, nil
	}
	return stripURLCredentials(url), true, nil
}

func stripURLCredentials(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.User = nil
	return parsed.String()
}

type CommitInfo struct {
	AuthorEmail string
	Timestamp   time.Time
}

func extractCommitHistory(ctx context.Context, repoPath string) ([]CommitInfo, error) {
	//nolint:gosec // G204: args are hardcoded git subcommands; repoPath is an internal trusted path
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "log", "--date-order", "--format=%ae%x09%aI")
	applyGitEnv(ctx, cmd)
	applyGitCeiling(cmd, repoPath)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := string(exitErr.Stderr)
			// Unborn branch (`git init` with no commits yet). Valid state —
			// treat as empty history so callers return GitMetadata with just
			// SourceURL rather than failing the whole analysis.
			if strings.Contains(stderr, "does not have any commits yet") {
				return nil, nil
			}
			if len(stderr) > 0 {
				return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr))
			}
		}
		return nil, err
	}

	var commits []CommitInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		email, tsStr, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			continue
		}
		ts, err := time.Parse(time.RFC3339, tsStr)
		if err != nil {
			continue
		}
		commits = append(commits, CommitInfo{
			AuthorEmail: email,
			Timestamp:   ts,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning git log output: %w", err)
	}
	return commits, nil
}

type CommitMetrics struct {
	RecentAuthorsCount     int
	MaxMonthlyAuthorsCount int
	MaxMonthlyWindowStart  time.Time
	MaxMonthlyWindowEnd    time.Time
	FirstCommit            time.Time
	LatestHumanCommit      time.Time
	CommitCount            int
	HumanCommitCount       int
}

// isBotCommit checks if a commit email is from an automated bot (not a human).
// GitHub bots are identified by the [bot] suffix in their email username.
// Examples of bot emails:
//   - github-actions[bot]@users.noreply.github.com
//   - dependabot[bot]@users.noreply.github.com
//   - renovate[bot]@users.noreply.github.com
//
// Important: GitHub privacy emails (e.g., "9087854+username@users.noreply.github.com")
// are from REAL HUMANS with privacy settings enabled and should NOT be filtered.
// The presence of [bot] in the email is the definitive indicator of a bot account.
func isBotCommit(email string) bool {
	email = strings.ToLower(email)

	if strings.Contains(email, "[bot]@") {
		return true
	}

	knownBotEmails := []string{
		"noreply@github.com",
		"support@dependabot.com",
	}

	return slices.Contains(knownBotEmails, email)
}

// analyzeCommitMetrics calculates statistics from commit history
func analyzeCommitMetrics(commits []CommitInfo) CommitMetrics {
	if len(commits) == 0 {
		return CommitMetrics{}
	}

	// Filter out bot commits
	var nonBotCommits []CommitInfo
	for _, c := range commits {
		if !isBotCommit(c.AuthorEmail) {
			nonBotCommits = append(nonBotCommits, c)
		}
	}

	humanCommitCount := len(nonBotCommits)

	if len(nonBotCommits) == 0 {
		nonBotCommits = commits // fallback to all commits if all are bots
	}

	// Find first and latest human commits
	firstCommit := nonBotCommits[len(nonBotCommits)-1].Timestamp
	latestCommit := nonBotCommits[0].Timestamp

	// Calculate recent authors (last 365 days)
	oneYearAgo := time.Now().AddDate(-1, 0, 0)
	recentAuthors := make(map[string]bool)
	for _, c := range nonBotCommits {
		if c.Timestamp.After(oneYearAgo) {
			recentAuthors[strings.ToLower(c.AuthorEmail)] = true
		}
	}

	// Calculate max monthly authors (30-day rolling window)
	rollingWindow := calculateMaxMonthlyAuthors(nonBotCommits)

	return CommitMetrics{
		RecentAuthorsCount:     len(recentAuthors),
		MaxMonthlyAuthorsCount: rollingWindow.MaxAuthors,
		MaxMonthlyWindowStart:  rollingWindow.WindowStart,
		MaxMonthlyWindowEnd:    rollingWindow.WindowEnd,
		FirstCommit:            firstCommit,
		LatestHumanCommit:      latestCommit,
		CommitCount:            len(commits),
		HumanCommitCount:       humanCommitCount,
	}
}

type RollingWindowResult struct {
	MaxAuthors  int
	WindowStart time.Time
	WindowEnd   time.Time
}

// calculateMaxMonthlyAuthors finds the maximum unique authors in any 30-day rolling window
// This implements the same logic as the Python reference using pandas resample and rolling windows
func calculateMaxMonthlyAuthors(commits []CommitInfo) RollingWindowResult {
	if len(commits) == 0 {
		return RollingWindowResult{}
	}

	// Build a map of date -> set of authors who committed on that date
	dailyAuthors := make(map[string]map[string]bool)

	for _, commit := range commits {
		// Use date string as key (YYYY-MM-DD)
		dateKey := commit.Timestamp.Format("2006-01-02")

		if dailyAuthors[dateKey] == nil {
			dailyAuthors[dateKey] = make(map[string]bool)
		}
		dailyAuthors[dateKey][strings.ToLower(commit.AuthorEmail)] = true
	}

	// Find earliest and latest dates
	var minDate, maxDate time.Time
	for _, commit := range commits {
		if minDate.IsZero() || commit.Timestamp.Before(minDate) {
			minDate = commit.Timestamp
		}
		if maxDate.IsZero() || commit.Timestamp.After(maxDate) {
			maxDate = commit.Timestamp
		}
	}

	if minDate.IsZero() {
		return RollingWindowResult{}
	}

	// Normalize to start of day
	minDate = time.Date(minDate.Year(), minDate.Month(), minDate.Day(), 0, 0, 0, 0, time.UTC)
	maxDate = time.Date(maxDate.Year(), maxDate.Month(), maxDate.Day(), 0, 0, 0, 0, time.UTC)

	result := RollingWindowResult{}

	// For each day, calculate the rolling 30-day window sum of unique daily authors
	for currentDate := minDate; !currentDate.After(maxDate); currentDate = currentDate.AddDate(0, 0, 1) {
		windowStart := currentDate.AddDate(0, 0, -29) // 30-day window (today + previous 29 days)

		// Collect all unique authors in this 30-day window
		windowAuthors := make(map[string]bool)

		for d := windowStart; !d.After(currentDate); d = d.AddDate(0, 0, 1) {
			dateKey := d.Format("2006-01-02")
			if authors, exists := dailyAuthors[dateKey]; exists {
				for author := range authors {
					windowAuthors[author] = true
				}
			}
		}

		if len(windowAuthors) > result.MaxAuthors {
			result.MaxAuthors = len(windowAuthors)
			result.WindowStart = windowStart
			result.WindowEnd = currentDate
		}
	}

	return result
}
