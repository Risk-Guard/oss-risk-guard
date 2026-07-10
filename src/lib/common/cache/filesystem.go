package cache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"

	"go.uber.org/zap"
)

// FilesystemBackend implements Backend using the local filesystem.
type FilesystemBackend struct {
	baseDir string
}

// NewFilesystemBackend creates a new filesystem-based cache backend.
// baseDir is the root directory for cache storage (typically the outputDir from context).
func NewFilesystemBackend(baseDir string) *FilesystemBackend {
	return &FilesystemBackend{
		baseDir: baseDir,
	}
}

// Get retrieves cached data from the filesystem.
func (f *FilesystemBackend) Get(ctx context.Context, key string, maxAge time.Duration) ([]byte, time.Time, error) {
	logger := ctxutil.GetLogger(ctx)
	cachePath := filepath.Join(f.baseDir, key)

	// Check if cache file exists
	info, err := os.Stat(cachePath)
	if os.IsNotExist(err) {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("checking cache file: %w", err)
	}

	// Check if cache is expired
	storedAt := info.ModTime()
	age := time.Since(storedAt)
	if age > maxAge {
		logger.Debug("cache expired",
			zap.String("cache_key", key),
			zap.Duration("age", age),
			zap.Duration("max_age", maxAge))
		return nil, time.Time{}, nil
	}

	// Read cache file
	data, err := os.ReadFile(cachePath) // #nosec G304 - cachePath is derived from baseDir and validated key
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("reading cache file: %w", err)
	}

	logger.Debug("cache hit",
		zap.String("cache_key", key),
		zap.Duration("age", age))

	return data, storedAt, nil
}

// Set stores data in the filesystem cache.
// url, statusCode, and headers are ignored by the filesystem backend (only used by BigQuery).
func (f *FilesystemBackend) Set(ctx context.Context, key string, data []byte) error {
	logger := ctxutil.GetLogger(ctx)

	cachePath := filepath.Join(f.baseDir, key)

	// Create cache directory
	cacheDir := filepath.Dir(cachePath)
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	// Write to a temp file in the same directory, then rename into place. Rename
	// is atomic within a filesystem, so concurrent writers targeting the same key
	// (e.g. the HEAD and published clone nodes when a version's gitHead equals
	// HEAD) each publish a complete file and one wins wholesale — a reader never
	// observes the torn, half-written archive a bare os.WriteFile would leave.
	tmp, err := os.CreateTemp(cacheDir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp cache file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp cache file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("setting cache file permissions: %w", err)
	}
	if err := os.Rename(tmpPath, cachePath); err != nil {
		return fmt.Errorf("publishing cache file: %w", err)
	}

	logger.Debug("cache write",
		zap.String("cache_key", key),
		zap.String("path", cachePath))

	return nil
}

// Close is a no-op for FilesystemBackend as there are no resources to release.
func (f *FilesystemBackend) Close() error {
	return nil
}
