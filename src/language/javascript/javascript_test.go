package javascript

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	npmregistry "github.com/Risk-Guard/oss-risk-guard/src/registry/npm"

	"go.uber.org/zap"
)

// TestExtractPackageMetadata_RepositoryPrecedence verifies that the source URL
// is resolved from the analyzed version's own repository field, falling back to
// the top-level (hoisted-from-latest) value. This is the @types/json5@0.0.29
// case: top-level is null because latest (a deprecated stub) dropped the field,
// but the analyzed version declares the real repository.
func TestExtractPackageMetadata_RepositoryPrecedence(t *testing.T) {
	ctx := ctxutil.SetLogger(context.Background(), zap.NewNop())
	j := &JavaScript{}

	ghRepo := func(url string) map[string]any {
		return map[string]any{"type": "git", "url": url}
	}

	tests := []struct {
		name     string
		topLevel any
		version  any
		wantURL  string // "" means expect nil SourceURL
	}{
		{
			name:     "version-level used when top-level absent",
			topLevel: nil,
			version:  ghRepo("https://github.com/DefinitelyTyped/DefinitelyTyped.git"),
			wantURL:  "https://github.com/DefinitelyTyped/DefinitelyTyped",
		},
		{
			name:     "version-level wins over top-level",
			topLevel: ghRepo("https://github.com/other/latest-repo.git"),
			version:  ghRepo("https://github.com/real/this-version.git"),
			wantURL:  "https://github.com/real/this-version",
		},
		{
			name:     "top-level used when version absent",
			topLevel: ghRepo("https://github.com/top/level.git"),
			version:  nil,
			wantURL:  "https://github.com/top/level",
		},
		{
			name:     "neither present yields nil",
			topLevel: nil,
			version:  nil,
			wantURL:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &npmregistry.NPMPackageData{
				Name:       "@types/json5",
				DistTags:   map[string]string{"latest": "2.2.0"},
				Repository: tt.topLevel,
				Versions: map[string]npmregistry.NPMVersionDetails{
					"0.0.29": {Repository: tt.version},
				},
			}
			pkg := models.PackageInfo{Name: "@types/json5", Version: "0.0.29"}

			meta, _, _, err := j.ExtractPackageMetadata(ctx, pkg, data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantURL == "" {
				if meta.SourceURL != nil {
					t.Fatalf("expected nil SourceURL, got %q", *meta.SourceURL)
				}
				return
			}
			if meta.SourceURL == nil {
				t.Fatalf("expected SourceURL %q, got nil", tt.wantURL)
			}
			if *meta.SourceURL != tt.wantURL {
				t.Errorf("SourceURL = %q, want %q", *meta.SourceURL, tt.wantURL)
			}
		})
	}
}

// TestExtractPackageMetadata_SourceDirectory verifies that npm's
// repository.directory subpath is captured into SourceDirectory. This is the
// monorepo case (e.g. @types/canvas-confetti lives in DefinitelyTyped under
// types/canvas-confetti) that lets git-history analysis scope to the package.
func TestExtractPackageMetadata_SourceDirectory(t *testing.T) {
	ctx := ctxutil.SetLogger(context.Background(), zap.NewNop())
	j := &JavaScript{}

	tests := []struct {
		name    string
		repo    any
		wantDir string // "" means expect nil SourceDirectory
	}{
		{
			name:    "object with directory",
			repo:    map[string]any{"type": "git", "url": "https://github.com/DefinitelyTyped/DefinitelyTyped.git", "directory": "types/canvas-confetti"},
			wantDir: "types/canvas-confetti",
		},
		{
			name:    "directory with surrounding slashes is trimmed",
			repo:    map[string]any{"type": "git", "url": "https://github.com/DefinitelyTyped/DefinitelyTyped.git", "directory": "/types/canvas-confetti/"},
			wantDir: "types/canvas-confetti",
		},
		{
			name:    "object without directory yields nil",
			repo:    map[string]any{"type": "git", "url": "https://github.com/user/repo.git"},
			wantDir: "",
		},
		{
			name:    "string repository has no directory",
			repo:    "https://github.com/user/repo.git",
			wantDir: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &npmregistry.NPMPackageData{
				Name:     "@types/canvas-confetti",
				DistTags: map[string]string{"latest": "1.9.0"},
				Versions: map[string]npmregistry.NPMVersionDetails{
					"1.9.0": {Repository: tt.repo},
				},
			}
			pkg := models.PackageInfo{Name: "@types/canvas-confetti", Version: "1.9.0"}

			meta, _, _, err := j.ExtractPackageMetadata(ctx, pkg, data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantDir == "" {
				if meta.SourceDirectory != nil {
					t.Fatalf("expected nil SourceDirectory, got %q", *meta.SourceDirectory)
				}
				return
			}
			if meta.SourceDirectory == nil {
				t.Fatalf("expected SourceDirectory %q, got nil", tt.wantDir)
			}
			if *meta.SourceDirectory != tt.wantDir {
				t.Errorf("SourceDirectory = %q, want %q", *meta.SourceDirectory, tt.wantDir)
			}
		})
	}
}
