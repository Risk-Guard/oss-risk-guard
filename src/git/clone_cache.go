package git

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"github.com/Risk-Guard/oss-risk-guard/src/archive"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"time"
)

const cloneMetaFile = ".rg-clone-meta.json"

const cloneCacheMaxAge = 365 * 24 * time.Hour

var validHexSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// IsFullSHA returns true if s is a 40-character lowercase hex SHA.
func IsFullSHA(s string) bool {
	return validHexSHA.MatchString(s)
}

func cloneCacheKey(patternsHash, normalizedURL, commitSHA string) (string, error) {
	if !validHexSHA.MatchString(commitSHA) {
		return "", fmt.Errorf("invalid commit SHA for cache key: %q", commitSHA)
	}
	urlHash := CacheKey(normalizedURL)
	return fmt.Sprintf("clone-cache/v3/content/%s/%s/%s.tar.gz", patternsHash, urlHash, commitSHA), nil
}

// GetCachedClone retrieves a cached repo tar.gz, writing it to a temp file.
// Returns ("", false, nil) on cache miss.
func GetCachedClone(ctx context.Context, backend cache.Backend, patternsHash, normalizedURL, commitSHA string) (string, bool, error) {
	key, err := cloneCacheKey(patternsHash, normalizedURL, commitSHA)
	if err != nil {
		return "", false, err
	}
	data, _, err := backend.Get(ctx, key, cloneCacheMaxAge)
	if err != nil {
		return "", false, fmt.Errorf("getting clone cache: %w", err)
	}
	if data == nil {
		return "", false, nil
	}

	tmpFile, err := os.CreateTemp("", "clone-cache-*.tar.gz")
	if err != nil {
		return "", false, fmt.Errorf("creating temp file: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name()) //nolint:gosec // Path from os.CreateTemp
		return "", false, fmt.Errorf("writing temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name()) //nolint:gosec // Path from os.CreateTemp
		return "", false, fmt.Errorf("closing temp file: %w", err)
	}

	return tmpFile.Name(), true, nil
}

// PutCachedClone creates a tar.gz of repoDir and stores it in the cache backend.
func PutCachedClone(ctx context.Context, backend cache.Backend, patternsHash, normalizedURL, commitSHA, repoDir string) error {
	tmpFile, err := os.CreateTemp("", "clone-cache-put-*.tar.gz")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tarPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tarPath) }()

	if err := archive.CreateTarGz(repoDir, tarPath); err != nil {
		return fmt.Errorf("creating tar.gz: %w", err)
	}

	data, err := os.ReadFile(tarPath) //nolint:gosec // tarPath is a temp file we just created
	if err != nil {
		return fmt.Errorf("reading tar.gz: %w", err)
	}

	key, err := cloneCacheKey(patternsHash, normalizedURL, commitSHA)
	if err != nil {
		return err
	}
	if err := backend.Set(ctx, key, data); err != nil {
		return fmt.Errorf("storing clone cache: %w", err)
	}

	return nil
}

// ExtractCachedRepo extracts a cached tar.gz into destDir.
func ExtractCachedRepo(tarPath, destDir string) error {
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return fmt.Errorf("creating dest dir: %w", err)
	}
	return archive.ExtractTarGz(tarPath, destDir)
}

// CleanupTarFile removes a temp tar file, ignoring errors.
func CleanupTarFile(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

// IsPrivateRequest returns true if the request has authentication that indicates a private repo.
func IsPrivateRequest(ctx context.Context, sourceURL string) (bool, error) {
	if ctxutil.GetSourceToken(ctx) != "" {
		return true, nil
	}

	parsed, err := url.Parse(sourceURL)
	if err != nil {
		return false, fmt.Errorf("parsing source URL: %w", err)
	}
	return parsed.User != nil, nil
}

// WriteCloneMeta serializes GitMetadata as .rg-clone-meta.json inside repoDir.
func WriteCloneMeta(repoDir string, meta *models.GitMetadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshaling clone meta: %w", err)
	}
	return os.WriteFile(filepath.Join(repoDir, cloneMetaFile), data, 0o600)
}

// ReadCloneMeta deserializes .rg-clone-meta.json from repoDir.
func ReadCloneMeta(repoDir string) (*models.GitMetadata, error) {
	data, err := os.ReadFile(filepath.Join(repoDir, cloneMetaFile)) //nolint:gosec // path is constructed from known repoDir
	if err != nil {
		return nil, fmt.Errorf("reading clone meta: %w", err)
	}
	var meta models.GitMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("unmarshaling clone meta: %w", err)
	}
	return &meta, nil
}

// RemoveCloneMeta deletes .rg-clone-meta.json from repoDir, ignoring errors.
func RemoveCloneMeta(repoDir string) {
	_ = os.Remove(filepath.Join(repoDir, cloneMetaFile))
}
