package pathutil

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// currentBuggyLogic replicates the current path resolution logic
// to demonstrate the bug identified in PR review
func currentBuggyLogic(manifestPath, repoRoot string) string {
	if !filepath.IsAbs(manifestPath) && !strings.HasPrefix(manifestPath, repoRoot) {
		manifestPath = filepath.Join(repoRoot, manifestPath)
	}
	return manifestPath
}

func TestPathBoundaryBug(t *testing.T) {
	tests := []struct {
		name         string
		repoRoot     string
		manifestPath string
		wantBuggy    string // what current buggy code produces
		wantCorrect  string // what correct behavior should be
	}{
		{
			name:         "relative path - should join",
			repoRoot:     "/home/user/repo",
			manifestPath: "subdir/package.json",
			wantBuggy:    "/home/user/repo/subdir/package.json",
			wantCorrect:  "/home/user/repo/subdir/package.json",
		},
		{
			name:         "absolute path under repoRoot - should not change",
			repoRoot:     "/home/user/repo",
			manifestPath: "/home/user/repo/subdir/package.json",
			wantBuggy:    "/home/user/repo/subdir/package.json",
			wantCorrect:  "/home/user/repo/subdir/package.json",
		},
		{
			name:         "BUG: similar prefix but different directory",
			repoRoot:     "/home/user/repo",
			manifestPath: "/home/user/repos/package.json", // note: repos not repo
			wantBuggy:    "/home/user/repos/package.json", // BUG: passes through unchanged
			wantCorrect:  "/home/user/repo/home/user/repos/package.json",
		},
		{
			name:         "BUG: repoRoot as prefix of different path",
			repoRoot:     "/tmp/test",
			manifestPath: "/tmp/test-other/file.json",
			wantBuggy:    "/tmp/test-other/file.json", // BUG: passes through
			wantCorrect:  "/tmp/test/tmp/test-other/file.json",
		},
		{
			name:         "absolute path completely outside repoRoot",
			repoRoot:     "/home/user/repo",
			manifestPath: "/other/path/package.json",
			wantBuggy:    "/other/path/package.json", // BUG: passes through since IsAbs is true
			wantCorrect:  "/home/user/repo/other/path/package.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := currentBuggyLogic(tt.manifestPath, tt.repoRoot)
			if got != tt.wantBuggy {
				t.Errorf("currentBuggyLogic() = %q, want %q", got, tt.wantBuggy)
			}

			// Demonstrate the bug exists
			if tt.wantBuggy != tt.wantCorrect {
				t.Logf("BUG CONFIRMED: current logic returns %q but correct behavior should be %q", tt.wantBuggy, tt.wantCorrect)
			}
		})
	}
}

func TestResolveManifestPath(t *testing.T) {
	tests := []struct {
		name         string
		repoRoot     string
		manifestPath string
		want         string
	}{
		{
			name:         "relative path",
			repoRoot:     "/home/user/repo",
			manifestPath: "subdir/package.json",
			want:         "/home/user/repo/subdir/package.json",
		},
		{
			name:         "absolute path under repoRoot",
			repoRoot:     "/home/user/repo",
			manifestPath: "/home/user/repo/subdir/package.json",
			want:         "/home/user/repo/subdir/package.json",
		},
		{
			name:         "similar prefix different directory - should join",
			repoRoot:     "/home/user/repo",
			manifestPath: "/home/user/repos/package.json",
			want:         "/home/user/repo/home/user/repos/package.json",
		},
		{
			name:         "repoRoot as prefix of different path - should join",
			repoRoot:     "/tmp/test",
			manifestPath: "/tmp/test-other/file.json",
			want:         "/tmp/test/tmp/test-other/file.json",
		},
		{
			name:         "absolute path outside repoRoot",
			repoRoot:     "/home/user/repo",
			manifestPath: "/other/path/package.json",
			want:         "/home/user/repo/other/path/package.json",
		},
		{
			name:         "nested relative path",
			repoRoot:     "/project",
			manifestPath: "packages/core/package.json",
			want:         "/project/packages/core/package.json",
		},
		{
			name:         "relative path already under repoRoot",
			repoRoot:     ".oss-score/source/github.com/Risk-Guard/public-test/repo",
			manifestPath: ".oss-score/source/github.com/Risk-Guard/public-test/repo/bun/package.json",
			want:         ".oss-score/source/github.com/Risk-Guard/public-test/repo/bun/package.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveManifestPath(tt.manifestPath, tt.repoRoot)
			if got != tt.want {
				t.Errorf("ResolveManifestPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCommonNonSourceDirectoryNames(t *testing.T) {
	expectedDirs := []string{"test", "tests", "__tests__", "fixtures", "testdata", "example", "examples"}
	for _, dir := range expectedDirs {
		if !slices.Contains(CommonNonSourceDirectoryNames, dir) {
			t.Errorf("expected %q to be in CommonNonSourceDirectoryNames", dir)
		}
	}
}

func TestMergeSkipDirsWithCommonNonSourceDirs(t *testing.T) {
	ecosystemDirs := []string{"node_modules", "vendor"}
	merged := MergeSkipDirsWithCommonNonSourceDirs(ecosystemDirs)

	if !slices.Contains(merged, "node_modules") {
		t.Error("expected merged to contain node_modules")
	}
	if !slices.Contains(merged, "test") {
		t.Error("expected merged to contain test")
	}
	if !slices.Contains(merged, "fixtures") {
		t.Error("expected merged to contain fixtures")
	}
}

func TestShouldSkipDir_WithNonSourceDirectories(t *testing.T) {
	skipDirs := MergeSkipDirsWithCommonNonSourceDirs([]string{"node_modules"})

	tests := []struct {
		name     string
		dirName  string
		expected bool
	}{
		{"node_modules", "node_modules", true},
		{"test dir", "test", true},
		{"tests dir", "tests", true},
		{"fixtures dir", "fixtures", true},
		{"__tests__ dir", "__tests__", true},
		{"example dir", "example", true},
		{"examples dir", "examples", true},
		{"regular src", "src", false},
		{"packages dir", "packages", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldSkipDir(tt.dirName, skipDirs)
			if got != tt.expected {
				t.Errorf("ShouldSkipDir(%q) = %v, want %v", tt.dirName, got, tt.expected)
			}
		})
	}
}
