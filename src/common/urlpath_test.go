package common

import "testing"

func TestNormalizeSourceURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "github with tree path",
			input:    "https://github.com/rails/rails/tree/v8.1.2/actionpack",
			expected: "https://github.com/rails/rails",
		},
		{
			name:     "github with blob path",
			input:    "https://github.com/org/repo/blob/main/file.md",
			expected: "https://github.com/org/repo",
		},
		{
			name:     "github with commit path",
			input:    "https://github.com/org/repo/commit/abc123",
			expected: "https://github.com/org/repo",
		},
		{
			name:     "github with issues path",
			input:    "https://github.com/org/repo/issues/123",
			expected: "https://github.com/org/repo",
		},
		{
			name:     "http upgrade to https",
			input:    "http://github.com/org/repo",
			expected: "https://github.com/org/repo",
		},
		{
			name:     "http upgrade with tree path",
			input:    "http://github.com/rails/rails/tree/main",
			expected: "https://github.com/rails/rails",
		},
		{
			name:     "git@ SCP-style SSH",
			input:    "git@github.com:org/repo.git",
			expected: "https://github.com/org/repo",
		},
		{
			name:     "simple https github URL unchanged",
			input:    "https://github.com/org/repo",
			expected: "https://github.com/org/repo",
		},
		{
			name:     "gitlab URL with path",
			input:    "https://gitlab.com/org/repo/tree/main/src",
			expected: "https://gitlab.com/org/repo",
		},
		{
			name:     "bitbucket URL with path",
			input:    "https://bitbucket.org/org/repo/src/master/README.md",
			expected: "https://bitbucket.org/org/repo",
		},
		{
			name:     "unknown host unchanged",
			input:    "https://example.com/org/repo/tree/main",
			expected: "https://example.com/org/repo/tree/main",
		},
		{
			name:     "invalid path returns unchanged",
			input:    "https://github.com/",
			expected: "https://github.com/",
		},
		{
			name:     "single segment path returns unchanged",
			input:    "https://github.com/org",
			expected: "https://github.com/org",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := NormalizeSourceURL(tc.input)
			if result != tc.expected {
				t.Errorf("NormalizeSourceURL(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestExtractOwnerRepo(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantOwner string
		wantRepo  string
		wantOK    bool
	}{
		{
			name:      "simple path",
			input:     "/org/repo",
			wantOwner: "org",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "path with extra segments",
			input:     "/org/repo/tree/main/src",
			wantOwner: "org",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "path without leading slash",
			input:     "org/repo",
			wantOwner: "org",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "path with .git suffix",
			input:     "org/repo.git",
			wantOwner: "org",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "empty path",
			input:     "",
			wantOwner: "",
			wantRepo:  "",
			wantOK:    false,
		},
		{
			name:      "single segment",
			input:     "/org",
			wantOwner: "",
			wantRepo:  "",
			wantOK:    false,
		},
		{
			name:      "empty owner",
			input:     "//repo",
			wantOwner: "",
			wantRepo:  "",
			wantOK:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owner, repo, ok := ExtractOwnerRepo(tc.input)
			if owner != tc.wantOwner || repo != tc.wantRepo || ok != tc.wantOK {
				t.Errorf("ExtractOwnerRepo(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.input, owner, repo, ok, tc.wantOwner, tc.wantRepo, tc.wantOK)
			}
		})
	}
}
