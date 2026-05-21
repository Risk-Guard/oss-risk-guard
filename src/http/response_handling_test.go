package http

import (
	"testing"
)

func TestTruncateBodyPreview(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		maxLen   int
		expected string
	}{
		{
			name:     "empty body",
			body:     []byte(""),
			maxLen:   200,
			expected: "",
		},
		{
			name:     "short body",
			body:     []byte("short"),
			maxLen:   200,
			expected: "short",
		},
		{
			name:     "exactly maxLen",
			body:     []byte("12345"),
			maxLen:   5,
			expected: "12345",
		},
		{
			name:     "longer than maxLen",
			body:     []byte("this is a very long error message that should be truncated"),
			maxLen:   20,
			expected: "this is a very long ...",
		},
		{
			name:     "maxLen zero",
			body:     []byte("any text"),
			maxLen:   0,
			expected: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateBodyPreview(tt.body, tt.maxLen)
			if result != tt.expected {
				t.Errorf("TruncateBodyPreview() = %q, want %q", result, tt.expected)
			}
		})
	}
}
