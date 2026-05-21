package licenses

import (
	"testing"
)

func TestConstructTextURL_EncodesSpecialCharacters(t *testing.T) {
	sourceURL := "https://github.com/test/repo"

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "space in filename",
			path:     "LICENSE (copy).txt",
			expected: "https://raw.githubusercontent.com/test/repo/abc123/LICENSE%20%28copy%29.txt",
		},
		{
			name:     "hash in filename",
			path:     "LICENSE#2.md",
			expected: "https://raw.githubusercontent.com/test/repo/abc123/LICENSE%232.md",
		},
		{
			name:     "special chars in nested path",
			path:     "docs/licenses/MIT License.txt",
			expected: "https://raw.githubusercontent.com/test/repo/abc123/docs/licenses/MIT%20License.txt",
		},
		{
			name:     "normal path unchanged",
			path:     "LICENSE",
			expected: "https://raw.githubusercontent.com/test/repo/abc123/LICENSE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConstructTextURL(&sourceURL, "abc123", tt.path)
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if *result != tt.expected {
				t.Errorf("got %s, want %s", *result, tt.expected)
			}
		})
	}
}

func TestConstructTextURL_NilSourceURL(t *testing.T) {
	result := ConstructTextURL(nil, "abc123", "LICENSE")
	if result == nil || *result != "<unsupported>" {
		t.Errorf("expected <unsupported>, got %v", result)
	}
}

func TestConstructTextURL_EmptySourceURL(t *testing.T) {
	empty := ""
	result := ConstructTextURL(&empty, "abc123", "LICENSE")
	if result == nil || *result != "<unsupported>" {
		t.Errorf("expected <unsupported>, got %v", result)
	}
}

func TestConstructTextURL_UnsupportedHost(t *testing.T) {
	sourceURL := "https://unknown.example.com/test/repo"
	result := ConstructTextURL(&sourceURL, "abc123", "LICENSE")
	if result == nil || *result != "<unsupported>" {
		t.Errorf("expected <unsupported>, got %v", result)
	}
}

func TestConstructTextURL_GitLab(t *testing.T) {
	sourceURL := "https://gitlab.com/test/repo"
	result := ConstructTextURL(&sourceURL, "abc123", "LICENSE")
	expected := "https://gitlab.com/test/repo/-/raw/abc123/LICENSE"
	if result == nil || *result != expected {
		t.Errorf("got %v, want %s", result, expected)
	}
}

func TestConstructTextURL_Bitbucket(t *testing.T) {
	sourceURL := "https://bitbucket.org/test/repo"
	result := ConstructTextURL(&sourceURL, "abc123", "LICENSE")
	expected := "https://bitbucket.org/test/repo/raw/abc123/LICENSE"
	if result == nil || *result != expected {
		t.Errorf("got %v, want %s", result, expected)
	}
}
