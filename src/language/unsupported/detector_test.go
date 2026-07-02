package unsupported

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindManifestInfo(t *testing.T) {
	tests := []struct {
		filename  string
		wantMatch bool
		wantLang  string
		wantEco   string
	}{
		{"go.mod", true, "Go", "go"},
		{"go.sum", true, "Go", "go"},
		{"Cargo.toml", true, "Rust", "cargo"},
		{"pom.xml", true, "Java", "maven"},
		{"build.gradle", true, "Java", "maven"},
		{"composer.json", true, "PHP", "packagist"},
		{"mix.exs", true, "Elixir", "hex"},
		{"Pipfile", true, "Python", "pypi"},
		{"yarn.lock", true, "JavaScript/Node", "npm"},
		// Glob suffix matches
		{"foo.csproj", true, "C#/.NET", "nuget"},
		{"bar.cabal", true, "Haskell", "hackage"},
		{"myapp.gemspec", false, "", ""}, // gemspec is SUPPORTED, should not match
		// No match
		{"package.json", false, "", ""},     // package.json is SUPPORTED
		{"requirements.txt", false, "", ""}, // requirements.txt is SUPPORTED
		{"pyproject.toml", false, "", ""},   // pyproject.toml is SUPPORTED
		{"random.txt", false, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			info := FindManifestInfo(tt.filename)
			if tt.wantMatch {
				if info == nil {
					t.Errorf("expected match for %s, got nil", tt.filename)
					return
				}
				if info.Language != tt.wantLang {
					t.Errorf("expected language %s, got %s", tt.wantLang, info.Language)
				}
				if info.Ecosystem != tt.wantEco {
					t.Errorf("expected ecosystem %s, got %s", tt.wantEco, info.Ecosystem)
				}
			} else {
				if info != nil {
					t.Errorf("expected no match for %s, got %+v", tt.filename, info)
				}
			}
		})
	}
}

func TestDetectUnsupportedManifests(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create test files
	files := []string{
		"go.mod",
		"go.sum",
		"subdir/Cargo.toml",
		"package.json",        // supported, should not be detected
		"requirements.txt",    // supported, should not be detected
		"node_modules/go.mod", // should be skipped (in node_modules)
	}

	for _, f := range files {
		path := filepath.Join(tmpDir, f)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}

	// Also create node_modules directory
	if err := os.MkdirAll(filepath.Join(tmpDir, "node_modules"), 0o750); err != nil {
		t.Fatalf("failed to create node_modules: %v", err)
	}

	detected, err := DetectUnsupportedManifests(tmpDir)
	if err != nil {
		t.Fatalf("DetectUnsupportedManifests failed: %v", err)
	}

	// Should detect: go.mod, go.sum, subdir/Cargo.toml
	// Should NOT detect: package.json, requirements.txt, node_modules/go.mod
	if len(detected) != 3 {
		t.Errorf("expected 3 detected manifests, got %d: %+v", len(detected), detected)
	}

	// Verify the detected files
	foundGoMod := false
	foundGoSum := false
	foundCargo := false
	for _, d := range detected {
		switch d.RelPath {
		case "go.mod":
			foundGoMod = true
			if d.Language != "Go" {
				t.Errorf("go.mod should be Go language, got %s", d.Language)
			}
		case "go.sum":
			foundGoSum = true
		case filepath.Join("subdir", "Cargo.toml"):
			foundCargo = true
			if d.Language != "Rust" {
				t.Errorf("Cargo.toml should be Rust language, got %s", d.Language)
			}
		}
	}

	if !foundGoMod {
		t.Error("expected to find go.mod")
	}
	if !foundGoSum {
		t.Error("expected to find go.sum")
	}
	if !foundCargo {
		t.Error("expected to find Cargo.toml")
	}
}

func TestManifestInfo_Matches(t *testing.T) {
	tests := []struct {
		manifest ManifestInfo
		filename string
		want     bool
	}{
		{ManifestInfo{Filename: "go.mod"}, "go.mod", true},
		{ManifestInfo{Filename: "go.mod"}, "go.sum", false},
		{ManifestInfo{GlobSuffix: ".csproj"}, "foo.csproj", true},
		{ManifestInfo{GlobSuffix: ".csproj"}, "bar.csproj", true},
		{ManifestInfo{GlobSuffix: ".csproj"}, ".csproj", false}, // too short
		{ManifestInfo{GlobSuffix: ".cabal"}, "mypackage.cabal", true},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := tt.manifest.Matches(tt.filename)
			if got != tt.want {
				t.Errorf("Matches(%s) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestSparseCheckoutPatternsCoversAllManifests(t *testing.T) {
	patternSet := make(map[string]bool)
	for _, p := range SparseCheckoutPatterns {
		patternSet[p] = true
	}

	for _, m := range Manifests {
		var expectedPattern string
		if m.Filename != "" {
			expectedPattern = "**/" + m.Filename
		} else if m.GlobSuffix != "" {
			expectedPattern = "**/*" + m.GlobSuffix
		}

		if expectedPattern == "" {
			t.Errorf("Manifest %+v has neither Filename nor GlobSuffix", m)
			continue
		}

		if !patternSet[expectedPattern] {
			t.Errorf("Manifest %s (%s) missing from SparseCheckoutPatterns: expected %q",
				m.Language, m.PackageManager, expectedPattern)
		}
	}
}
