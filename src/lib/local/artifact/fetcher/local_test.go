package localfetcher

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func createTestTarball(t *testing.T) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte(`{"name":"test-pkg","version":"1.0.0","scripts":{"postinstall":"echo hello"}}`)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "package/package.json",
		Mode: 0o644,
		Size: int64(len(content)),
	}))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

func setupTestContext(t *testing.T) (context.Context, string) {
	outputDir := t.TempDir()
	tempDir := t.TempDir()
	ctx := context.Background()
	ctx = ctxutil.SetLogger(ctx, zap.NewNop())
	ctx = ctxutil.SetTempDir(ctx, tempDir)
	cfg := &environment.Config{}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = runpath.SetOutputDir(ctx, outputDir)
	return ctx, outputDir
}

func TestFetch_HashMismatch_SkipsExtraction(t *testing.T) {
	tarball := createTestTarball(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball)
	}))
	defer server.Close()

	ctx, _ := setupTestContext(t)

	pkg := models.PackageInfo{Ecosystem: "npm", Name: "test-pkg", Version: "1.0.0"}
	dist := &models.DistributionInfo{
		URL:           server.URL + "/test.tgz",
		Filename:      "test.tgz",
		Hash:          "0000000000000000000000000000000000000000000000000000000000000000",
		HashAlgorithm: "sha256",
	}

	extraction, err := New().Fetch(ctx, pkg, dist)
	require.NoError(t, err)

	require.False(t, extraction.Verified, "extraction should not be verified on hash mismatch")
	require.NotNil(t, extraction.VerifyError, "verify error should be set")
	require.Contains(t, *extraction.VerifyError, "hash mismatch")

	require.Empty(t, extraction.Files, "Files should be empty on hash mismatch")
}

func TestFetch_ValidHash_Extracts(t *testing.T) {
	tarball := createTestTarball(t)

	hash := sha256.Sum256(tarball)
	expectedHash := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball)
	}))
	defer server.Close()

	ctx, _ := setupTestContext(t)

	pkg := models.PackageInfo{Ecosystem: "npm", Name: "test-pkg", Version: "1.0.0"}
	dist := &models.DistributionInfo{
		URL:           server.URL + "/test.tgz",
		Filename:      "test.tgz",
		Hash:          expectedHash,
		HashAlgorithm: "sha256",
	}

	extraction, err := New().Fetch(ctx, pkg, dist)
	require.NoError(t, err)

	require.True(t, extraction.Verified, "extraction should be verified")
	require.Nil(t, extraction.VerifyError)

	require.NotEmpty(t, extraction.Files, "Files should not be empty")
	require.Contains(t, extraction.Files, "package/package.json", "Files should contain package.json")
}

func TestFetch_NoHashProvided_Extracts(t *testing.T) {
	tarball := createTestTarball(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball)
	}))
	defer server.Close()

	ctx, _ := setupTestContext(t)

	pkg := models.PackageInfo{Ecosystem: "npm", Name: "test-pkg", Version: "1.0.0"}
	dist := &models.DistributionInfo{
		URL:           server.URL + "/test.tgz",
		Filename:      "test.tgz",
		Hash:          "",
		HashAlgorithm: "",
	}

	extraction, err := New().Fetch(ctx, pkg, dist)
	require.NoError(t, err)

	require.False(t, extraction.Verified, "extraction should not be verified when no hash provided")
	require.NotNil(t, extraction.VerifyError)
	require.Contains(t, *extraction.VerifyError, "no hash provided by registry")

	require.NotEmpty(t, extraction.Files, "Files should not be empty even without hash")
	require.Contains(t, extraction.Files, "package/package.json", "Files should contain package.json")
}
