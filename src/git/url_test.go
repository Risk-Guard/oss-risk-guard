package git

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeCacheURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "basic https",
			input: "https://github.com/expressjs/express",
			want:  "https://github.com/expressjs/express",
		},
		{
			name:  "strips .git suffix",
			input: "https://github.com/expressjs/express.git",
			want:  "https://github.com/expressjs/express",
		},
		{
			name:  "strips trailing slash",
			input: "https://github.com/expressjs/express/",
			want:  "https://github.com/expressjs/express",
		},
		{
			name:  "strips .git and trailing slash",
			input: "https://github.com/expressjs/express.git/",
			want:  "https://github.com/expressjs/express",
		},
		{
			name:  "lowercases host",
			input: "https://GitHub.COM/expressjs/express",
			want:  "https://github.com/expressjs/express",
		},
		{
			name:  "lowercases scheme",
			input: "HTTPS://github.com/expressjs/express",
			want:  "https://github.com/expressjs/express",
		},
		{
			name:  "strips userinfo",
			input: "https://x-access-token:ghp_abc123@github.com/expressjs/express",
			want:  "https://github.com/expressjs/express",
		},
		{
			name:  "preserves path case",
			input: "https://github.com/ExpressJS/Express",
			want:  "https://github.com/ExpressJS/Express",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeCacheURL(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCacheKey(t *testing.T) {
	normalized, err := NormalizeCacheURL("https://github.com/expressjs/express")
	require.NoError(t, err)

	key := CacheKey(normalized)
	require.Len(t, key, 64)

	key2 := CacheKey(normalized)
	require.Equal(t, key, key2)

	// .git suffix normalizes to the same URL, so keys should match
	normalizedWithGit, err := NormalizeCacheURL("https://github.com/expressjs/express.git")
	require.NoError(t, err)

	key3 := CacheKey(normalizedWithGit)
	require.Equal(t, key, key3)
}

func TestNormalizeCacheURL_EquivalentURLs(t *testing.T) {
	urls := []string{
		"https://github.com/expressjs/express",
		"https://github.com/expressjs/express.git",
		"https://github.com/expressjs/express/",
		"https://GitHub.COM/expressjs/express",
		"https://x-access-token:ghp_abc@github.com/expressjs/express.git",
	}

	var normalized []string
	for _, u := range urls {
		n, err := NormalizeCacheURL(u)
		require.NoError(t, err)
		normalized = append(normalized, n)
	}

	for i := 1; i < len(normalized); i++ {
		require.Equal(t, normalized[0], normalized[i],
			"URLs %q and %q should normalize to the same value", urls[0], urls[i])
	}
}
