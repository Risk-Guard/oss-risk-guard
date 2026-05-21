package pep508

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantName       string
		wantSpecifiers []string
		wantError      bool
	}{
		// Valid inline formats
		{
			name:           "simple version",
			input:          "pkg>=1.0",
			wantName:       "pkg",
			wantSpecifiers: []string{">=1.0"},
		},
		{
			name:           "v prefix version",
			input:          "pkg>=v1.0",
			wantName:       "pkg",
			wantSpecifiers: []string{">=v1.0"},
		},
		{
			name:           "V prefix uppercase",
			input:          "pkg>=V1.0",
			wantName:       "pkg",
			wantSpecifiers: []string{">=V1.0"},
		},
		{
			name:           "multiple specifiers",
			input:          "pkg>=1.0,<2.0",
			wantName:       "pkg",
			wantSpecifiers: []string{">=1.0", "<2.0"},
		},
		{
			name:           "triple equals",
			input:          "pkg===1.0.0",
			wantName:       "pkg",
			wantSpecifiers: []string{"===1.0.0"},
		},
		{
			name:           "tilde equals",
			input:          "pkg~=1.4.2",
			wantName:       "pkg",
			wantSpecifiers: []string{"~=1.4.2"},
		},
		{
			name:           "no specifiers",
			input:          "pkg",
			wantName:       "pkg",
			wantSpecifiers: []string{},
		},
		{
			name:           "wildcard version",
			input:          "pkg==1.*",
			wantName:       "pkg",
			wantSpecifiers: []string{"==1.*"},
		},
		{
			name:           "epoch version",
			input:          "pkg>=1!1.0",
			wantName:       "pkg",
			wantSpecifiers: []string{">=1!1.0"},
		},
		{
			name:           "pre-release version",
			input:          "pkg>=1.0a1",
			wantName:       "pkg",
			wantSpecifiers: []string{">=1.0a1"},
		},
		{
			name:           "post-release version",
			input:          "pkg>=1.0.post1",
			wantName:       "pkg",
			wantSpecifiers: []string{">=1.0.post1"},
		},
		{
			name:           "dev version",
			input:          "pkg>=1.0.dev0",
			wantName:       "pkg",
			wantSpecifiers: []string{">=1.0.dev0"},
		},
		{
			name:           "local version",
			input:          "pkg>=1.0+local",
			wantName:       "pkg",
			wantSpecifiers: []string{">=1.0+local"},
		},
		{
			name:           "not equal with wildcard",
			input:          "pytest!=8.1.*",
			wantName:       "pytest",
			wantSpecifiers: []string{"!=8.1.*"},
		},
		{
			name:           "not equal with wildcard and additional specifier",
			input:          "pytest!=8.1.*,>=6",
			wantName:       "pytest",
			wantSpecifiers: []string{"!=8.1.*", ">=6"},
		},

		// Valid parenthesized formats
		{
			name:           "parentheses format",
			input:          "pkg (>=1.0)",
			wantName:       "pkg",
			wantSpecifiers: []string{">=1.0"},
		},
		{
			name:           "parentheses multiple specifiers",
			input:          "pkg (>=1.0, <2.0)",
			wantName:       "pkg",
			wantSpecifiers: []string{">=1.0", "<2.0"},
		},

		// Malformed specs
		{
			name:      "empty input",
			input:     "",
			wantError: true,
		},
		{
			name:      "operator without version",
			input:     "pkg>=",
			wantName:  "pkg",
			wantError: true,
		},
		{
			name:      "trailing operator without version",
			input:     "pkg>=1.0,>=",
			wantName:  "pkg",
			wantError: true,
		},
		{
			name:      "middle operator without version",
			input:     "pkg>=1.0,>=,<2.0",
			wantName:  "pkg",
			wantError: true,
		},
		{
			name:      "unclosed parentheses",
			input:     "pkg (>=1.0",
			wantName:  "pkg",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Parse(tt.input)

			if tt.wantError {
				assert.NotEmpty(t, result.ParseError, "expected parse error")
			} else {
				assert.Empty(t, result.ParseError, "unexpected parse error: %s", result.ParseError)
			}

			if tt.wantName != "" {
				assert.Equal(t, tt.wantName, result.Name)
			}

			if tt.wantSpecifiers != nil {
				assert.Equal(t, tt.wantSpecifiers, result.Specifiers)
			}
		})
	}
}
