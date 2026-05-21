package git

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"strings"
)

// NormalizeCacheURL normalizes a source URL for use as a cache key component.
// Composes on NormalizeSourceURL (semantic normalization: known host upgrades, owner/repo extraction),
// then applies mechanical normalization (case folding, credential stripping, suffix cleanup).
func NormalizeCacheURL(rawURL string) (string, error) {
	normalized := common.NormalizeSourceURL(rawURL)
	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.User = nil
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	parsed.Path = strings.TrimSuffix(parsed.Path, ".git")

	return parsed.String(), nil
}

// CacheKey returns a sha256 hex digest of a normalized URL, suitable for use as a path component.
func CacheKey(normalizedURL string) string {
	h := sha256.Sum256([]byte(normalizedURL))
	return fmt.Sprintf("%x", h)
}
