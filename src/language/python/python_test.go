package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractExtraMarker(t *testing.T) {
	tests := []struct {
		name   string
		marker string
		want   *string
	}{
		{
			name:   "double quotes",
			marker: `extra == "dev"`,
			want:   ptr("dev"),
		},
		{
			name:   "single quotes",
			marker: `extra == 'test'`,
			want:   ptr("test"),
		},
		{
			name:   "no spaces",
			marker: `extra=="dev"`,
			want:   ptr("dev"),
		},
		{
			name:   "compound with python_version first",
			marker: `python_version >= "3.6" and extra == "dev"`,
			want:   ptr("dev"),
		},
		{
			name:   "compound with sys_platform",
			marker: `sys_platform == "win32" and extra == "dev"`,
			want:   ptr("dev"),
		},
		{
			name:   "no extra marker",
			marker: `python_version >= "3.6"`,
			want:   nil,
		},
		{
			name:   "empty string",
			marker: "",
			want:   nil,
		},
		{
			name:   "i18n extra",
			marker: `extra == "i18n"`,
			want:   ptr("i18n"),
		},
		{
			name:   "mismatched quotes double-single",
			marker: `extra == "dev'`,
			want:   nil,
		},
		{
			name:   "mismatched quotes single-double",
			marker: `extra == 'dev"`,
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractExtraMarker(tt.marker)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				assert.NotNil(t, got)
				assert.Equal(t, *tt.want, *got)
			}
		})
	}
}

func ptr(s string) *string {
	return &s
}
