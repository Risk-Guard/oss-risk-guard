package git

import (
	"context"
	"os"
	"path/filepath"
	"risk-guard/src/models"
	"testing"
	"time"

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

func TestCloneMetaRoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Truncate(time.Second)
	commitCount := 42
	meta := &models.GitMetadata{
		SourceURL:   "https://github.com/expressjs/express",
		Status:      "success",
		CollectedAt: &now,
		CommitCount: &commitCount,
	}

	require.NoError(t, WriteCloneMeta(dir, meta))

	got, err := ReadCloneMeta(dir)
	require.NoError(t, err)
	require.Equal(t, meta.SourceURL, got.SourceURL)
	require.Equal(t, meta.Status, got.Status)
	require.Equal(t, *meta.CommitCount, *got.CommitCount)
	require.True(t, meta.CollectedAt.Equal(*got.CollectedAt))

	require.FileExists(t, filepath.Join(dir, cloneMetaFile))
	RemoveCloneMeta(dir)
	_, err = os.Stat(filepath.Join(dir, cloneMetaFile))
	require.True(t, os.IsNotExist(err))
}

func TestReadCloneMeta_Missing(t *testing.T) {
	_, err := ReadCloneMeta(t.TempDir())
	require.Error(t, err)
}

func TestIsFullSHA(t *testing.T) {
	require.True(t, IsFullSHA("abc123def456abc123def456abc123def456abcd"))
	require.False(t, IsFullSHA("main"))
	require.False(t, IsFullSHA("abc123"))
	require.False(t, IsFullSHA(""))
	require.False(t, IsFullSHA("ABC123DEF456ABC123DEF456ABC123DEF456ABCD"))
}
