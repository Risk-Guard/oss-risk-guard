package archive

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		pattern string
		want    bool
	}{
		{
			name:    "exact match",
			path:    "package/package.json",
			pattern: "package/package.json",
			want:    true,
		},
		{
			name:    "glob suffix match",
			path:    "torch-2.0.0/setup.py",
			pattern: "**/setup.py",
			want:    true,
		},
		{
			name:    "glob nested match",
			path:    "some/deep/nested/setup.py",
			pattern: "**/setup.py",
			want:    true,
		},
		{
			name:    "no match",
			path:    "package/index.js",
			pattern: "package/package.json",
			want:    false,
		},
		{
			name:    "glob no match",
			path:    "package/setup.py.bak",
			pattern: "**/setup.py",
			want:    false,
		},
		{
			name:    "top level glob match",
			path:    "setup.py",
			pattern: "**/setup.py",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPattern(tt.path, tt.pattern)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMatchesAnyPattern(t *testing.T) {
	patterns := []string{"package/package.json", "**/setup.py"}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "matches first pattern",
			path: "package/package.json",
			want: true,
		},
		{
			name: "matches second pattern",
			path: "torch-2.0.0/setup.py",
			want: true,
		},
		{
			name: "matches neither",
			path: "README.md",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesAnyPattern(tt.path, patterns)
			require.Equal(t, tt.want, got)
		})
	}
}
