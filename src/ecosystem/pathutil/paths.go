package pathutil

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// CommonNonSourceDirectoryNames contains directory names that don't contain primary source manifests
// (tests, fixtures, examples, etc.) and may contain intentionally malformed files.
var CommonNonSourceDirectoryNames = []string{
	"test", "tests", "__tests__",
	"fixtures", "testdata", "test-fixtures", "test_fixtures",
	"spec", "specs", "__fixtures__", "__mocks__",
	"example", "examples",
}

// MergeSkipDirsWithCommonNonSourceDirs combines ecosystem-specific skip directories with common non-source directories.
func MergeSkipDirsWithCommonNonSourceDirs(ecosystemSkips []string) []string {
	combined := make([]string, 0, len(ecosystemSkips)+len(CommonNonSourceDirectoryNames))
	combined = append(combined, ecosystemSkips...)
	combined = append(combined, CommonNonSourceDirectoryNames...)
	return combined
}

func ShouldSkipDir(name string, skipDirs []string) bool {
	return slices.Contains(skipDirs, name)
}

func ResolveManifestPath(manifestPath, repoRoot string) string {
	rel, err := filepath.Rel(repoRoot, manifestPath)
	if err == nil && !strings.HasPrefix(rel, "..") {
		return manifestPath
	}
	return filepath.Join(repoRoot, manifestPath)
}

// WalkDirs walks the directory tree rooted at root, calling fn for each directory.
// Skips directories in skipDirs and directories starting with "." (except root).
func WalkDirs(root string, skipDirs []string, fn func(dir string, entries []fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		// Never skip the root directory even if its name matches a skip pattern
		if path != root {
			name := d.Name()
			if strings.HasPrefix(name, ".") || ShouldSkipDir(name, skipDirs) {
				return filepath.SkipDir
			}
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		return fn(path, entries)
	})
}
