package git

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCloneCacheKey(t *testing.T) {
	sha := "abc123def456abc123def456abc123def456abcd"
	pHash := "abcdef012345"
	key, err := cloneCacheKey(pHash, "https://github.com/expressjs/express", sha)
	require.NoError(t, err)
	urlHash := CacheKey("https://github.com/expressjs/express")
	expected := "clone-cache/v3/content/" + pHash + "/" + urlHash + "/" + sha + ".tar.gz"
	require.Equal(t, expected, key)
}

func TestCloneCacheKey_InvalidSHA(t *testing.T) {
	_, err := cloneCacheKey("abcdef012345", "https://github.com/expressjs/express", "not-a-sha")
	require.Error(t, err)

	_, err = cloneCacheKey("abcdef012345", "https://github.com/expressjs/express", "../../etc/passwd")
	require.Error(t, err)
}

func TestIsPrivateRequest(t *testing.T) {
	ctx := context.Background()

	isPrivate, err := IsPrivateRequest(ctx, "https://github.com/expressjs/express")
	require.NoError(t, err)
	require.False(t, isPrivate)

	isPrivate, err = IsPrivateRequest(ctx, "https://user:pass@github.com/foo/bar")
	require.NoError(t, err)
	require.True(t, isPrivate)
}

func TestExtractCachedRepo_MissingDir(t *testing.T) {
	err := ExtractCachedRepo("/nonexistent/file.tar.gz", t.TempDir())
	require.Error(t, err)
}

func TestIsFullSHA(t *testing.T) {
	require.True(t, IsFullSHA("abc123def456abc123def456abc123def456abcd"))
	require.False(t, IsFullSHA("main"))
	require.False(t, IsFullSHA("abc123"))
	require.False(t, IsFullSHA(""))
	require.False(t, IsFullSHA("ABC123DEF456ABC123DEF456ABC123DEF456ABCD"))
}
