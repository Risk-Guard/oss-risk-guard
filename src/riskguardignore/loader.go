package riskguardignore

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"risk-guard/src/ctxutil"
	"strings"

	"go.uber.org/zap"

	"github.com/bmatcuk/doublestar/v4"
)

const IgnoreFileName = ".riskguardignore"

// LoadIgnorePatterns reads a .riskguardignore file from the given repo path.
// Returns empty slice if file doesn't exist (not an error per Rule0).
func LoadIgnorePatterns(repoPath string) ([]string, error) {
	ignorePath := filepath.Join(repoPath, IgnoreFileName)

	file, err := os.Open(ignorePath) //nolint:gosec // path is derived from trusted repo path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize pattern
		pattern := normalizePattern(line)
		if pattern != "" {
			patterns = append(patterns, pattern)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return patterns, nil
}

// normalizePattern converts gitignore-style patterns to doublestar format.
func normalizePattern(pattern string) string {
	pattern = strings.TrimSpace(pattern)

	if strings.HasPrefix(pattern, "!") {
		return ""
	}

	pattern = strings.TrimPrefix(pattern, "/")
	pattern = strings.TrimSuffix(pattern, "/")

	if !strings.Contains(pattern, "/") && !strings.HasPrefix(pattern, "**/") {
		pattern = "**/" + pattern
	}

	return pattern
}

// ApplyIgnorePatterns loads .riskguardignore and deletes matching files from the repo.
// Returns nil if no patterns or file doesn't exist.
func ApplyIgnorePatterns(ctx context.Context, repoPath string) error {
	logger := ctxutil.GetLogger(ctx)

	patterns, err := LoadIgnorePatterns(repoPath)
	if err != nil {
		return err
	}
	if len(patterns) == 0 {
		return nil
	}

	logger.Debug("applying .riskguardignore patterns",
		zap.Int("pattern_count", len(patterns)),
		zap.Strings("patterns", patterns))

	// Collect paths to delete (can't delete while walking)
	var toDelete []string

	err = filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip .git directory and the ignore file itself
		if d.Name() == ".git" || d.Name() == IgnoreFileName {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, relErr := filepath.Rel(repoPath, path)
		if relErr != nil {
			return nil
		}

		// Check each pattern
		for _, pattern := range patterns {
			matched, matchErr := doublestar.Match(pattern, relPath)
			if matchErr != nil {
				logger.Debug("pattern match failed", zap.String("pattern", pattern), zap.Error(matchErr))
				continue
			}
			if matched {
				toDelete = append(toDelete, relPath)
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(toDelete) > 0 {
		logger.Info("deleting files matching .riskguardignore",
			zap.Int("file_count", len(toDelete)),
			zap.Strings("files", toDelete))
	}

	// Delete collected paths
	for _, relPath := range toDelete {
		fullPath := filepath.Join(repoPath, relPath)
		if err := os.RemoveAll(fullPath); err != nil {
			logger.Warn("failed to delete ignored file",
				zap.String("path", relPath),
				zap.Error(err))
		}
	}

	return nil
}
