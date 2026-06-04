package riskguardignore

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"

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

// AppendIgnorePatterns appends entries to <repoPath>/.riskguardignore, creating
// the file if absent and preserving any existing patterns and comments. An entry
// whose normalized form already matches a pattern in the file is skipped, so
// re-running init is idempotent. The raw (human-readable) entry is written, while
// dedup compares normalized forms — so "third_party" and "third_party/" collapse
// to one. Returns the entries actually written.
func AppendIgnorePatterns(repoPath string, entries []string) ([]string, error) {
	existing, err := LoadIgnorePatterns(repoPath)
	if err != nil {
		return nil, err
	}
	have := make(map[string]struct{}, len(existing))
	for _, p := range existing {
		have[p] = struct{}{}
	}

	var toWrite []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		norm := normalizePattern(e)
		if norm == "" {
			continue
		}
		if _, ok := have[norm]; ok {
			continue
		}
		have[norm] = struct{}{}
		toWrite = append(toWrite, e)
	}
	if len(toWrite) == 0 {
		return nil, nil
	}

	ignorePath := filepath.Join(repoPath, IgnoreFileName)
	file, err := os.OpenFile(ignorePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // path is derived from trusted repo path
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var b strings.Builder
	b.WriteString("\n# Added by risk-guard init\n")
	for _, e := range toWrite {
		b.WriteString(e)
		b.WriteString("\n")
	}
	if _, err := file.WriteString(b.String()); err != nil {
		return nil, err
	}
	return toWrite, nil
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

// Matcher tests repo-relative paths against loaded .riskguardignore patterns.
// A nil/empty Matcher matches nothing, so callers can use it unconditionally.
type Matcher struct {
	patterns []string
}

// NewMatcher loads .riskguardignore from repoPath into a Matcher. A missing
// file yields an empty matcher (matches nothing), per Rule0.
func NewMatcher(repoPath string) (*Matcher, error) {
	patterns, err := LoadIgnorePatterns(repoPath)
	if err != nil {
		return nil, err
	}
	return &Matcher{patterns: patterns}, nil
}

// Empty reports whether the matcher has no patterns.
func (m *Matcher) Empty() bool {
	return m == nil || len(m.patterns) == 0
}

// Match reports whether relPath (repo-relative) is excluded by any pattern.
// A pattern matches the path itself and, with gitignore directory semantics,
// anything beneath it — so "third_party" excludes "third_party/foo/setup.py".
func (m *Matcher) Match(relPath string) bool {
	if m == nil {
		return false
	}
	relPath = filepath.ToSlash(relPath)
	for _, p := range m.patterns {
		if matched, err := doublestar.Match(p, relPath); err == nil && matched {
			return true
		}
		if matched, err := doublestar.Match(p+"/**", relPath); err == nil && matched {
			return true
		}
	}
	return false
}

// ApplyIgnorePatterns loads .riskguardignore and deletes matching files from the repo.
// Returns nil if no patterns or file doesn't exist.
func ApplyIgnorePatterns(ctx context.Context, repoPath string) error {
	logger := ctxutil.GetLogger(ctx)

	matcher, err := NewMatcher(repoPath)
	if err != nil {
		return err
	}
	if matcher.Empty() {
		return nil
	}

	logger.Debug("applying .riskguardignore patterns",
		zap.Int("pattern_count", len(matcher.patterns)),
		zap.Strings("patterns", matcher.patterns))

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

		if matcher.Match(relPath) {
			toDelete = append(toDelete, relPath)
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
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
