package purl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuild_NPM(t *testing.T) {
	tests := []struct {
		name     string
		eco      string
		pkg      string
		version  string
		expected string
	}{
		{
			name:     "simple package",
			eco:      "npm",
			pkg:      "express",
			version:  "4.18.2",
			expected: "pkg:npm/express@4.18.2",
		},
		{
			name:     "scoped package",
			eco:      "npm",
			pkg:      "@angular/core",
			version:  "16.0.0",
			expected: "pkg:npm/%40angular/core@16.0.0",
		},
		{
			name:     "no version",
			eco:      "npm",
			pkg:      "lodash",
			version:  "",
			expected: "pkg:npm/lodash",
		},
		{
			name:     "uppercase ecosystem",
			eco:      "NPM",
			pkg:      "react",
			version:  "18.2.0",
			expected: "pkg:npm/react@18.2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Build(tt.eco, tt.pkg, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuild_PyPI(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		version  string
		expected string
	}{
		{
			name:     "simple package",
			pkg:      "requests",
			version:  "2.28.0",
			expected: "pkg:pypi/requests@2.28.0",
		},
		{
			name:     "underscore normalized to hyphen",
			pkg:      "typing_extensions",
			version:  "4.5.0",
			expected: "pkg:pypi/typing-extensions@4.5.0",
		},
		{
			name:     "uppercase normalized to lowercase",
			pkg:      "Django",
			version:  "4.2.0",
			expected: "pkg:pypi/django@4.2.0",
		},
		{
			name:     "dot normalized to hyphen",
			pkg:      "zope.interface",
			version:  "6.0",
			expected: "pkg:pypi/zope-interface@6.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Build("pypi", tt.pkg, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuild_RubyGems(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		version  string
		expected string
	}{
		{
			name:     "simple gem",
			pkg:      "rails",
			version:  "7.0.0",
			expected: "pkg:gem/rails@7.0.0",
		},
		{
			name:     "gem with hyphen",
			pkg:      "activerecord",
			version:  "7.0.0",
			expected: "pkg:gem/activerecord@7.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Build("rubygems", tt.pkg, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToAnalysisKey_Malformed(t *testing.T) {
	for _, purlStr := range []string{
		"pkg:npm/lodash@",
		"pkg:npm/@1.0.0",
		"pkg:npm/lodash@%ZZ",
		"pkg:npm/%ZZ@1.0.0",
	} {
		t.Run(purlStr, func(t *testing.T) {
			key, ok := ToAnalysisKey(purlStr)
			assert.False(t, ok)
			assert.Empty(t, key)
		})
	}
}

func TestBuild_OtherEcosystems(t *testing.T) {
	tests := []struct {
		name     string
		eco      string
		pkg      string
		version  string
		expected string
	}{
		{
			name:     "golang",
			eco:      "golang",
			pkg:      "github.com/gin-gonic/gin",
			version:  "v1.9.0",
			expected: "pkg:golang/github.com%2Fgin-gonic%2Fgin@v1.9.0",
		},
		{
			name:     "cargo",
			eco:      "cargo",
			pkg:      "serde",
			version:  "1.0.0",
			expected: "pkg:cargo/serde@1.0.0",
		},
		{
			name:     "unknown ecosystem uses lowercase name as type",
			eco:      "CustomEco",
			pkg:      "mypackage",
			version:  "1.0.0",
			expected: "pkg:customeco/mypackage@1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Build(tt.eco, tt.pkg, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}
