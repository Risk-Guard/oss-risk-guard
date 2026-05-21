package licenses

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsValidLicensePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"root LICENSE", "LICENSE", true},
		{"with extension", "LICENSE.txt", true},
		{"subdirectory", "src/LICENSE", true},
		{"COPYING", "COPYING", true},
		{"lowercase", "license", true},
		{"UNLICENSE", "UNLICENSE", true},
		{"unlicense lowercase", "unlicense", true},
		{"UNLICENSE with extension", "UNLICENSE.txt", true},

		{"test directory", "test/LICENSE", false},
		{"tests directory", "tests/LICENSE", false},
		{"nested test", "src/test/LICENSE", false},

		{"md extension", "LICENSE.md", true},
		{"rst extension", "LICENSE.rst", true},
		{"html extension", "LICENSE.html", true},
		{"htm extension", "LICENSE.htm", true},
		{"markdown extension", "LICENSE.markdown", true},

		{"Apache 2.0 version suffix", "LICENSE-Apache-2.0", true},
		{"GPL 3.0 version suffix", "LICENSE-GPL-3.0", true},

		{"typescript file", "types/license-checker/license-checker-tests.ts", false},
		{"go file", "pkg/license/license.go", false},
		{"python file", "license_checker.py", false},
		{"javascript file", "license-utils.js", false},
		{"java file", "LicenseChecker.java", false},
		{"rust file", "license.rs", false},
		{"c file", "license.c", false},
		{"json extension", "LICENSE.json", false},
		{"csv extension", "LICENSE.csv", false},
		{"svg extension", "LICENSE.svg", false},
		{"jpg extension", "LICENSE.jpg", false},
		{"png extension", "license.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidLicensePath(tt.path)
			if result != tt.expected {
				t.Errorf("isValidLicensePath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestRecursiveGlobPatterns(t *testing.T) {
	tmpDir := t.TempDir()

	testFiles := []string{
		"LICENSE",
		"LICENSE.txt",
		"LICENSE-MIT",
		"LICENSE-Apache",
		"MIT-LICENSE",
		"Apache-LICENCE",
		"BSD-LICENSE.txt",
		"UNLICENSE",
		"unlicense.txt",
		"COPYING",
		"COPYING-BSD",
		"GPL-COPYING",
		"src/LICENSE",
		"src/pkg/LICENSE",
		"src/pkg/subpkg/LICENCE",
		"src/pkg/LICENSE-MIT",
		"src/pkg/MIT-LICENSE",
		"docs/LICENSE.md",
		"vendor/lib/LICENSE",
		"vendor/lib/LICENSE-Apache-2.0",
		"vendor/lib/nested/COPYING.txt",
		"vendor/lib/nested/copying-mit",
		"vendor/lib/nested/bsd-license",
	}

	for _, file := range testFiles {
		fullPath := filepath.Join(tmpDir, file)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte("test license content"), 0o600); err != nil {
			t.Fatalf("Failed to create file %s: %v", fullPath, err)
		}
	}

	found, err := findLicenseFiles(tmpDir)
	if err != nil {
		t.Fatalf("findLicenseFiles() error: %v", err)
	}

	var relPaths []string
	for _, path := range found {
		rel, err := filepath.Rel(tmpDir, path)
		if err != nil {
			t.Fatalf("Failed to get relative path: %v", err)
		}
		relPaths = append(relPaths, filepath.ToSlash(rel))
	}

	expectedFiles := map[string]bool{
		"docs/LICENSE.md":               true,
		"LICENSE":                       true,
		"LICENSE.txt":                   true,
		"LICENSE-MIT":                   true,
		"LICENSE-Apache":                true,
		"MIT-LICENSE":                   true,
		"Apache-LICENCE":                true,
		"BSD-LICENSE.txt":               true,
		"UNLICENSE":                     true,
		"unlicense.txt":                 true,
		"COPYING":                       true,
		"COPYING-BSD":                   true,
		"GPL-COPYING":                   true,
		"src/LICENSE":                   true,
		"src/pkg/LICENSE":               true,
		"src/pkg/subpkg/LICENCE":        true,
		"src/pkg/LICENSE-MIT":           true,
		"src/pkg/MIT-LICENSE":           true,
		"vendor/lib/LICENSE":            true,
		"vendor/lib/LICENSE-Apache-2.0": true,
		"vendor/lib/nested/COPYING.txt": true,
		"vendor/lib/nested/copying-mit": true,
		"vendor/lib/nested/bsd-license": true,
	}

	foundMap := make(map[string]bool)
	for _, path := range relPaths {
		foundMap[path] = true
	}

	for expected := range expectedFiles {
		if !foundMap[expected] {
			t.Errorf("Expected to find %s but didn't", expected)
		}
	}

	if len(found) < len(expectedFiles) {
		t.Errorf("Expected at least %d license files, found %d", len(expectedFiles), len(found))
		t.Logf("Found files: %v", relPaths)
	}
}

func TestIsNumericExtension(t *testing.T) {
	tests := []struct {
		ext      string
		expected bool
	}{
		{".0", true},
		{".1", true},
		{".12", true},
		{".123", true},
		{"", false},
		{".", false},
		{".ts", false},
		{".go", false},
		{".md", false},
		{".txt", false},
		{".0a", false},
		{".a0", false},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			result := isNumericExtension(tt.ext)
			if result != tt.expected {
				t.Errorf("isNumericExtension(%q) = %v, want %v", tt.ext, result, tt.expected)
			}
		})
	}
}
