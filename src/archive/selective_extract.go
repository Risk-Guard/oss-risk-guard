package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const MaxTextFileSize = 1 * 1024 * 1024 // 1MB limit for text files

var TargetPatterns = map[string][]string{
	"npm":      {"package/package.json"},
	"pypi":     {"**/setup.py"},
	"rubygems": {"**/extconf.rb"},
}

func matchesAnyPattern(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchPattern(path, pattern) {
			return true
		}
	}
	return false
}

func matchPattern(path, pattern string) bool {
	if strings.HasPrefix(pattern, "**/") {
		suffix := pattern[3:]
		return strings.HasSuffix(path, "/"+suffix) || strings.HasSuffix(path, suffix) || path == suffix
	}
	matched, _ := filepath.Match(pattern, path)
	return matched
}

func ExtractTargetFiles(artifactPath string, patterns []string) (map[string]string, error) {
	f, err := os.Open(artifactPath) //nolint:gosec // Path from trusted source
	if err != nil {
		return nil, fmt.Errorf("opening archive %s: %w", filepath.Base(artifactPath), err)
	}
	defer func() { _ = f.Close() }()

	return ExtractTargetFilesFromReader(f, artifactPath, patterns)
}
