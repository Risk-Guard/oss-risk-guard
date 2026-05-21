package git

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
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

func AnalyzeRepository(repoPath string) (*models.GitMetadata, error) {
	// Open the repository
	repo, err := git.PlainOpenWithOptions(repoPath, &git.PlainOpenOptions{EnableDotGitCommonDir: true})
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	// Get remote origin URL
	sourceURL, found, err := getRemoteURL(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to read git remotes: %w", err)
	}
	if !found {
		// No origin remote found - falling back to absolute repository path
		absPath, err := filepath.Abs(repoPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
		}
		sourceURL = absPath
	}

	// Extract commit history
	commits, err := extractCommitHistory(repo)

	// Handle partial failure (shallow clone)
	var statusReason *string
	if err != nil {
		msg := err.Error()
		statusReason = &msg
		// If we have no commits at all, this is a complete failure
		if len(commits) == 0 {
			return &models.GitMetadata{
				SourceURL:    sourceURL,
				StatusReason: statusReason,
			}, nil
		}
		// Otherwise, continue with partial data
	}

	if len(commits) == 0 {
		// Empty repository
		return &models.GitMetadata{
			SourceURL: sourceURL,
		}, nil
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
		StatusReason:           statusReason,
	}
	if !metrics.MaxMonthlyWindowStart.IsZero() && !metrics.MaxMonthlyWindowEnd.IsZero() {
		metadata.MaxMonthlyWindowStart = &metrics.MaxMonthlyWindowStart
		metadata.MaxMonthlyWindowEnd = &metrics.MaxMonthlyWindowEnd
	}
	return metadata, nil
}

func getRemoteURL(repo *git.Repository) (string, bool, error) {
	remotes, err := repo.Remotes()
	if err != nil {
		return "", false, err // Real error - can't read remotes
	}

	for _, remote := range remotes {
		if remote.Config().Name == "origin" {
			if len(remote.Config().URLs) > 0 {
				return stripURLCredentials(remote.Config().URLs[0]), true, nil
			}
		}
	}

	return "", false, nil // No origin found - not an error
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

func extractCommitHistory(repo *git.Repository) ([]CommitInfo, error) {
	ref, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}

	// Get all references to handle shallow clones better
	commitIter, err := repo.Log(&git.LogOptions{
		From:  ref.Hash(),
		Order: git.LogOrderCommitterTime,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create log iterator: %w", err)
	}

	var commits []CommitInfo
	err = commitIter.ForEach(func(c *object.Commit) error {
		commits = append(commits, CommitInfo{
			AuthorEmail: c.Author.Email,
			Timestamp:   c.Author.When,
		})
		return nil
	})
	// Handle errors from iteration
	// Note: Shallow clones may cause "object not found" errors, but we still
	// return the commits we were able to collect
	if err != nil {
		// Log the error but return partial data
		// The caller can see we have some commits and decide how to proceed
		return commits, fmt.Errorf("partial commit history (shallow clone or incomplete): %w", err)
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
