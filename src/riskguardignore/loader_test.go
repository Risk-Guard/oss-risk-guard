package riskguardignore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
)

func TestMatcher_Match(t *testing.T) {
	// patterns are the normalized form LoadIgnorePatterns produces.
	m := &Matcher{patterns: []string{"**/third_party", "**/vendor", "**/*.generated.go", "src/tests"}}
	cases := []struct {
		path string
		want bool
	}{
		{"third_party", true},                      // the directory itself
		{"third_party/foo/setup.py", true},         // file beneath it
		{"a/third_party/x/requirements.txt", true}, // nested beneath it
		{"vendor/lib/package.json", true},
		{"src/tests", true},
		{"src/tests/conftest.py", true},
		{"pkg/foo.generated.go", true},
		{"requirements.txt", false},
		{"src/main.go", false},
		{"third_party_notes.txt", false}, // prefix only, not the dir
	}
	for _, c := range cases {
		if got := m.Match(c.path); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestMatcher_EmptyMatchesNothing(t *testing.T) {
	var nilM *Matcher
	if nilM.Match("anything") || !nilM.Empty() {
		t.Error("nil matcher should be empty and match nothing")
	}
	empty := &Matcher{}
	if empty.Match("x") || !empty.Empty() {
		t.Error("empty matcher should be empty and match nothing")
	}
}

func TestNormalizePattern(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"tests/", "**/tests"},
		{"tests", "**/tests"},
		{"src/tests/", "src/tests"},
		{"src/tests", "src/tests"},
		{"*.log", "**/*.log"},
		{"/tests/", "**/tests"},
		{"/tests", "**/tests"},
		{"!ignored", ""},
		{"  tests/  ", "**/tests"},
		{"vendor/", "**/vendor"},
		{"node_modules/", "**/node_modules"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizePattern(tt.input)
			if result != tt.expected {
				t.Errorf("normalizePattern(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyIgnorePatterns_DirectoryWithTrailingSlash(t *testing.T) {
	tmpDir := t.TempDir()

	testsDir := filepath.Join(tmpDir, "tests")
	if err := os.MkdirAll(filepath.Join(testsDir, "subdir"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testsDir, "test_file.go"), []byte("package test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testsDir, "subdir", "nested.go"), []byte("package nested"), 0o600); err != nil {
		t.Fatal(err)
	}

	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}

	ignoreContent := "tests/\n"
	if err := os.WriteFile(filepath.Join(tmpDir, IgnoreFileName), []byte(ignoreContent), 0o600); err != nil {
		t.Fatal(err)
	}

	log, _ := logger.NewLogger("error")
	ctx := ctxutil.SetLogger(context.Background(), log)

	if err := ApplyIgnorePatterns(ctx, tmpDir); err != nil {
		t.Fatalf("ApplyIgnorePatterns failed: %v", err)
	}

	if _, err := os.Stat(testsDir); !os.IsNotExist(err) {
		t.Errorf("tests/ directory should have been deleted, but still exists")
	}

	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		t.Errorf("src/ directory should NOT have been deleted")
	}
	if _, err := os.Stat(filepath.Join(srcDir, "main.go")); os.IsNotExist(err) {
		t.Errorf("src/main.go should NOT have been deleted")
	}
}

func TestApplyIgnorePatterns_NoIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "file.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}

	log, _ := logger.NewLogger("error")
	ctx := ctxutil.SetLogger(context.Background(), log)

	if err := ApplyIgnorePatterns(ctx, tmpDir); err != nil {
		t.Fatalf("ApplyIgnorePatterns should not fail when no ignore file: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "file.go")); os.IsNotExist(err) {
		t.Errorf("file.go should still exist")
	}
}

func TestLoadIgnorePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	ignoreContent := `# Comment line
tests/
vendor/

# Another comment
*.log
`
	if err := os.WriteFile(filepath.Join(tmpDir, IgnoreFileName), []byte(ignoreContent), 0o600); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadIgnorePatterns(tmpDir)
	if err != nil {
		t.Fatalf("LoadIgnorePatterns failed: %v", err)
	}

	expected := []string{"**/tests", "**/vendor", "**/*.log"}
	if len(patterns) != len(expected) {
		t.Fatalf("expected %d patterns, got %d: %v", len(expected), len(patterns), patterns)
	}
	for i, p := range patterns {
		if p != expected[i] {
			t.Errorf("pattern[%d] = %q, want %q", i, p, expected[i])
		}
	}
}

func TestApplyIgnorePatterns_Patterns(t *testing.T) {
	tests := []struct {
		name          string
		files         map[string]string
		ignorePattern string
		shouldDelete  []string
		shouldKeep    []string
	}{
		{
			name: "glob pattern *.log",
			files: map[string]string{
				"debug.log": "debug",
				"error.log": "error",
				"main.go":   "package main",
			},
			ignorePattern: "*.log\n",
			shouldDelete:  []string{"debug.log", "error.log"},
			shouldKeep:    []string{"main.go"},
		},
		{
			name: "file pattern .env*",
			files: map[string]string{
				".env":       "SECRET=123",
				".env.local": "LOCAL=456",
				"main.go":    "package main",
			},
			ignorePattern: ".env*\n",
			shouldDelete:  []string{".env", ".env.local"},
			shouldKeep:    []string{"main.go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			for name, content := range tt.files {
				if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := os.WriteFile(filepath.Join(tmpDir, IgnoreFileName), []byte(tt.ignorePattern), 0o600); err != nil {
				t.Fatal(err)
			}

			log, _ := logger.NewLogger("error")
			ctx := ctxutil.SetLogger(context.Background(), log)

			if err := ApplyIgnorePatterns(ctx, tmpDir); err != nil {
				t.Fatalf("ApplyIgnorePatterns failed: %v", err)
			}

			for _, name := range tt.shouldDelete {
				if _, err := os.Stat(filepath.Join(tmpDir, name)); !os.IsNotExist(err) {
					t.Errorf("%s should have been deleted", name)
				}
			}
			for _, name := range tt.shouldKeep {
				if _, err := os.Stat(filepath.Join(tmpDir, name)); os.IsNotExist(err) {
					t.Errorf("%s should NOT have been deleted", name)
				}
			}
		})
	}
}

func TestApplyIgnorePatterns_NestedPath(t *testing.T) {
	tmpDir := t.TempDir()

	genDir := filepath.Join(tmpDir, "src", "generated")
	if err := os.MkdirAll(genDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(genDir, "file.go"), []byte("package gen"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "src", "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, IgnoreFileName), []byte("src/generated/\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	log, _ := logger.NewLogger("error")
	ctx := ctxutil.SetLogger(context.Background(), log)

	if err := ApplyIgnorePatterns(ctx, tmpDir); err != nil {
		t.Fatalf("ApplyIgnorePatterns failed: %v", err)
	}

	if _, err := os.Stat(genDir); !os.IsNotExist(err) {
		t.Errorf("src/generated/ should have been deleted")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "src", "main.go")); os.IsNotExist(err) {
		t.Errorf("src/main.go should NOT have been deleted")
	}
}

func TestApplyIgnorePatterns_SkipsGitDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, IgnoreFileName), []byte(".git\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	log, _ := logger.NewLogger("error")
	ctx := ctxutil.SetLogger(context.Background(), log)

	if err := ApplyIgnorePatterns(ctx, tmpDir); err != nil {
		t.Fatalf("ApplyIgnorePatterns failed: %v", err)
	}

	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		t.Errorf(".git directory should NOT have been deleted (always skipped)")
	}
	if _, err := os.Stat(filepath.Join(gitDir, "config")); os.IsNotExist(err) {
		t.Errorf(".git/config should NOT have been deleted")
	}
}

func TestApplyIgnorePatterns_MultiplePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	for _, dir := range []string{"tests", "vendor", "src"} {
		if err := os.MkdirAll(filepath.Join(tmpDir, dir), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, dir, "file.go"), []byte("package "+dir), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(tmpDir, IgnoreFileName), []byte("tests/\nvendor/\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	log, _ := logger.NewLogger("error")
	ctx := ctxutil.SetLogger(context.Background(), log)

	if err := ApplyIgnorePatterns(ctx, tmpDir); err != nil {
		t.Fatalf("ApplyIgnorePatterns failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "tests")); !os.IsNotExist(err) {
		t.Errorf("tests/ should have been deleted")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "vendor")); !os.IsNotExist(err) {
		t.Errorf("vendor/ should have been deleted")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "src")); os.IsNotExist(err) {
		t.Errorf("src/ should NOT have been deleted")
	}
}
