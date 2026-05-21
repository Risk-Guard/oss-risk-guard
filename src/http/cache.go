package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"

	"github.com/avast/retry-go/v4"
	"go.uber.org/zap"
)

// cacheKey returns the relative cache key for a URL (without outputDir prefix or .json extension)
func cacheKey(url string) string {
	hash := sha256.Sum256([]byte(url))
	hashStr := hex.EncodeToString(hash[:])
	return filepath.Join("http-cache", hashStr)
}

// readCache attempts to read cached HTTP response for a URL.
// Returns nil if cache doesn't exist or is expired.
func readCache[T any](ctx context.Context, backend cache.Backend, url, customCacheKey string, maxAge time.Duration) (*T, error) {
	var key string
	if customCacheKey != "" {
		key = customCacheKey
	} else {
		key = cacheKey(url)
	}

	key += ".json"

	// Get from backend
	data, _, err := backend.Get(ctx, key, maxAge)
	if err != nil {
		return nil, fmt.Errorf("backend get: %w", err)
	}
	if data == nil {
		return nil, nil
	}

	// Parse JSON
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing cached response: %w", err)
	}

	return &result, nil
}

// writeCache writes HTTP response to cache for a URL.
// Only caches successful responses (2xx status codes).
func writeCache[T any](ctx context.Context, backend cache.Backend, url, customCacheKey string, response *T, statusCode int) error {
	logger := ctxutil.GetLogger(ctx)
	if statusCode < 200 || statusCode >= 300 {
		logger.Debug("skipping cache for non-2xx response",
			zap.String("url", url),
			zap.Int("status_code", statusCode))
		return nil
	}

	var key string
	if customCacheKey != "" {
		key = customCacheKey
	} else {
		key = cacheKey(url)
	}
	key += ".json"

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling response: %w", err)
	}

	if err := backend.Set(ctx, key, data); err != nil {
		return fmt.Errorf("backend set: %w", err)
	}

	return nil
}

// CacheOptions holds optional cache configuration
type CacheOptions struct {
	CacheKey string        // Optional custom cache key relative to outputDir, e.g. "nvd/CVE-2023-1234" becomes {outputDir}/nvd/CVE-2023-1234.json
	MaxAge   time.Duration // Optional max age (defaults to HTTP_CACHE_MAX_AGE_DAYS env var or 1 day)
}

// GetJSONCached is a cached variant of GetJSON that stores responses in the output directory.
// It checks the cache first and falls back to GetJSON on cache miss.
// Cache location: {outputDir}/http-cache/{sha256(url)}.json (or custom CacheKey if provided)
// Cache max age: HTTP_CACHE_MAX_AGE_DAYS env var (default: 1 day) or custom MaxAge if provided
func GetJSONCached[T any](ctx context.Context, url string, cacheOpts *CacheOptions, opts ...RequestOption) (*T, error) {
	backend := cache.GetCacheBackend(ctx)

	// Set defaults
	customCacheKey := ""
	maxAge := environment.GetSharedConfig(ctx).GetCacheMaxAge()

	if cacheOpts != nil {
		if cacheOpts.CacheKey != "" {
			customCacheKey = cacheOpts.CacheKey
		}
		if cacheOpts.MaxAge > 0 {
			maxAge = cacheOpts.MaxAge
		}
	}

	// Try reading from cache
	cached, err := readCache[T](ctx, backend, url, customCacheKey, maxAge)
	if err != nil {
		return nil, fmt.Errorf("reading cache: %w", err)
	}
	if cached != nil {
		return cached, nil
	}

	// Cache miss - fetch from network with retry
	var statusCode int
	result, err := retry.DoWithData(
		func() (*T, error) {
			data, sc, err := getJSONOnce[T](ctx, url, opts...)
			if err == nil {
				statusCode = sc
			}
			return data, err
		},
		DefaultRetryOptions(ctx, url)...,
	)
	if err != nil {
		return nil, err
	}

	if err := writeCache(ctx, backend, url, customCacheKey, result, statusCode); err != nil {
		return nil, fmt.Errorf("failed to write cache: %w", err)
	}

	return result, nil
}

// postCacheKey generates a cache key for a POST request based on URL and request body.
func postCacheKey(url string, reqBody any) (string, error) {
	// Marshal the request body to get a stable representation
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request body: %w", err)
	}

	// Hash the combination of URL and body
	combined := url + string(bodyBytes)
	hash := sha256.Sum256([]byte(combined))
	hashStr := hex.EncodeToString(hash[:])
	return filepath.Join("http-cache", hashStr), nil
}

// PostJSONCached is a cached variant of PostJSON that stores responses in the output directory.
// It checks the cache first based on the URL and request body, and falls back to PostJSON on cache miss.
// Cache location: {outputDir}/http-cache/{sha256(url+body)}.json (or custom CacheKey if provided)
// Cache max age: HTTP_CACHE_MAX_AGE_DAYS env var (default: 1 day) or custom MaxAge if provided
func PostJSONCached[T any](ctx context.Context, url string, reqBody any, cacheOpts *CacheOptions, opts ...RequestOption) (*T, error) {
	backend := cache.GetCacheBackend(ctx)

	var err error

	// Set defaults
	customCacheKey := ""
	maxAge := environment.GetSharedConfig(ctx).GetCacheMaxAge()

	if cacheOpts != nil {
		if cacheOpts.CacheKey != "" {
			customCacheKey = cacheOpts.CacheKey
		}
		if cacheOpts.MaxAge > 0 {
			maxAge = cacheOpts.MaxAge
		}
	}

	// Generate cache key from request body if custom key not provided
	cacheKeyForLookup := customCacheKey
	if cacheKeyForLookup == "" {
		cacheKeyForLookup, err = postCacheKey(url, reqBody)
		if err != nil {
			return nil, fmt.Errorf("generating cache key: %w", err)
		}
	}

	// Try reading from cache
	cached, err := readCache[T](ctx, backend, url, cacheKeyForLookup, maxAge)
	if err != nil {
		return nil, fmt.Errorf("reading cache: %w", err)
	}
	if cached != nil {
		return cached, nil
	}

	// Cache miss - fetch from network with retry, capturing metadata
	var statusCode int
	result, err := retry.DoWithData(
		func() (*T, error) {
			data, sc, err := postJSONOnce[T](ctx, url, reqBody, opts...)
			if err == nil {
				// Capture metadata on success
				statusCode = sc
			}
			return data, err
		},
		DefaultRetryOptions(ctx, url)...,
	)
	if err != nil {
		return nil, err
	}

	if err := writeCache(ctx, backend, url, cacheKeyForLookup, result, statusCode); err != nil {
		return nil, fmt.Errorf("failed to write cache: %w", err)
	}

	return result, nil
}
