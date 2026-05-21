package licenses

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/licenses/patterns"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/bmatcuk/doublestar/v4"
)

var (
	invalidLicenseDirs     = []string{"test", "tests", "example", "examples", "docs"}
	validLicenseExtensions = []string{
		"", ".txt", ".md", ".markdown", ".rst", ".html", ".htm",
	}
)

// ScanLicenseFiles walks sourceDir for candidate LICENSE/COPYING file paths.
// It does not read file contents — SPDX matching (IdentifyLicenses) re-reads
// from disk so that license texts don't get duplicated into persisted outputs.
// Files that pass globbing but fail isValidLicensePath are skipped silently.
// Symlinks and paths that escape sourceDir are also skipped to keep the
// G304 suppression in ReadLicenseFile honest.
func ScanLicenseFiles(sourceDir string) ([]models.LicenseFile, error) {
	licensePaths, err := findLicenseFiles(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to find license files: %w", err)
	}

	files := make([]models.LicenseFile, 0, len(licensePaths))
	for _, path := range licensePaths {
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			continue
		}
		if !isValidLicensePath(relPath) {
			continue
		}
		files = append(files, models.LicenseFile{Path: relPath})
	}

	return files, nil
}

// ReadLicenseFile reads relPath under sourceDir, refusing to follow symlinks
// or escape sourceDir. Returns the file contents.
func ReadLicenseFile(sourceDir, relPath string) (string, error) {
	resolvedRoot, err := filepath.EvalSymlinks(sourceDir)
	if err != nil {
		return "", fmt.Errorf("resolving source dir: %w", err)
	}

	candidate := filepath.Join(sourceDir, relPath)
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to read symlink: %s", relPath)
	}

	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes source dir: %s", relPath)
	}

	// #nosec G304 -- resolved path is Lstat'd non-symlink and confirmed under sourceDir
	content, err := os.ReadFile(resolved)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// findLicenseFiles globs for candidate license paths under sourceDir. Symlinks
// (file or dir) are rejected via Lstat + a containment check against the
// symlink-resolved sourceDir, so a hostile symlink in the working tree can't
// trick the scanner into matching a file outside the repo.
func findLicenseFiles(sourceDir string) ([]string, error) {
	resolvedRoot, err := filepath.EvalSymlinks(sourceDir)
	if err != nil {
		return nil, err
	}

	var matches []string
	seen := make(map[string]bool)

	for _, pattern := range patterns.GlobPatterns() {
		fullPattern := filepath.Join(sourceDir, pattern)
		files, err := doublestar.FilepathGlob(fullPattern)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			if seen[file] {
				continue
			}
			seen[file] = true

			info, err := os.Lstat(file)
			if err != nil || info.IsDir() {
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			resolved, err := filepath.EvalSymlinks(file)
			if err != nil {
				continue
			}
			rel, err := filepath.Rel(resolvedRoot, resolved)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			matches = append(matches, file)
		}
	}

	return matches, nil
}

// isValidLicensePath checks if the path is a valid license file location
func isValidLicensePath(relPath string) bool {
	lowerPath := strings.ToLower(relPath)

	for _, dirName := range invalidLicenseDirs {
		if strings.Contains(lowerPath, fmt.Sprintf("/%s/", dirName)) {
			return false
		}
		if strings.HasPrefix(lowerPath, fmt.Sprintf("%s/", dirName)) {
			return false
		}
	}
	ext := strings.ToLower(filepath.Ext(relPath))
	return slices.Contains(validLicenseExtensions, ext) || isNumericExtension(ext)
}

// isNumericExtension returns true for extensions like ".0", ".1" that result from
// filepath.Ext parsing version-suffixed files (e.g. LICENSE-Apache-2.0 → ext ".0").
func isNumericExtension(ext string) bool {
	if len(ext) < 2 || ext[0] != '.' {
		return false
	}
	for _, c := range ext[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
