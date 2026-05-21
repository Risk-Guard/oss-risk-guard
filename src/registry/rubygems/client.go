package rubygems

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	httputil "risk-guard/src/http"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
}

func NewClient(baseURL string) *Client {
	return &Client{
		httpClient: httputil.DefaultHTTPClient(),
		baseURL:    baseURL,
	}
}

type APIDependency struct {
	Name         string `json:"name"`
	Requirements string `json:"requirements"`
}

type Dependencies struct {
	Development []APIDependency `json:"development"`
	Runtime     []APIDependency `json:"runtime"`
}

type VersionInfo struct {
	Number     string `json:"number"`
	CreatedAt  string `json:"created_at"`
	BuiltAt    string `json:"built_at"`
	Prerelease bool   `json:"prerelease"`
}

// RubyGemsOwner represents an owner from the RubyGems owners API
type RubyGemsOwner struct {
	ID     int    `json:"id"`
	Handle string `json:"handle"`
	Email  string `json:"email,omitempty"`
}

func (c *Client) FetchVersions(ctx context.Context, packageName string) ([]VersionInfo, error) {
	url := fmt.Sprintf("%s/api/v1/versions/%s.json", c.baseURL, packageName)

	cacheOpts := &httputil.CacheOptions{
		CacheKey: filepath.Join("rubygems", "versions", packageName),
		MaxAge:   24 * time.Hour,
	}

	versions, err := httputil.GetJSONCached[[]VersionInfo](ctx, url, cacheOpts)
	if err != nil {
		if statusCode, ok := httputil.GetStatusCodeFromError(err); ok && statusCode == http.StatusNotFound {
			return nil, fmt.Errorf("package not found")
		}
		return nil, fmt.Errorf("failed to fetch version data: %w", err)
	}

	return *versions, nil
}

// FetchOwners fetches gem owners from the RubyGems API
func (c *Client) FetchOwners(ctx context.Context, packageName string) ([]RubyGemsOwner, error) {
	url := fmt.Sprintf("%s/api/v1/gems/%s/owners.json", c.baseURL, packageName)

	cacheOpts := &httputil.CacheOptions{
		CacheKey: filepath.Join("rubygems", "owners", packageName),
		MaxAge:   24 * time.Hour,
	}

	owners, err := httputil.GetJSONCached[[]RubyGemsOwner](ctx, url, cacheOpts)
	if err != nil {
		if statusCode, ok := httputil.GetStatusCodeFromError(err); ok && statusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch owners: %w", err)
	}

	return *owners, nil
}

// RubyGemsV2VersionResponse represents the v2 API response for version-specific data
type RubyGemsV2VersionResponse struct {
	Name          string          `json:"name"`
	Version       string          `json:"version"`
	Authors       string          `json:"authors"`
	Info          string          `json:"info"`
	Licenses      []string        `json:"licenses"`
	SourceCodeURI string          `json:"source_code_uri"`
	HomepageURI   string          `json:"homepage_uri"`
	Dependencies  Dependencies    `json:"dependencies"`
	CreatedAt     string          `json:"created_at"`
	GemURI        string          `json:"gem_uri"`
	SHA           string          `json:"sha"`
	SpecSHA       string          `json:"spec_sha"`
	Owners        []RubyGemsOwner `json:"owners,omitempty"`
}

// FetchPackageVersionWithMetadata fetches version-specific package data using v2 API.
// Uses the /api/v2/rubygems/{gem}/versions/{version}.json endpoint.
func (c *Client) FetchPackageVersionWithMetadata(packageName, version string) (*RubyGemsV2VersionResponse, *RubyGemsFetchMetadata, error) {
	url := fmt.Sprintf("%s/api/v2/rubygems/%s/versions/%s.json", c.baseURL, packageName, version)
	fetchedAt := time.Now()

	// #nosec G107
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch package data: %w", err)
	}

	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	bodyBytes, err := httputil.ReadResponseBody(resp)
	if err != nil {
		return nil, nil, err
	}

	metadata := &RubyGemsFetchMetadata{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		FetchedAt:  fetchedAt,
		URL:        url,
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, metadata, nil
		}
		bodyPreview := httputil.TruncateBodyPreview(bodyBytes, 200)
		if resp.StatusCode >= 500 {
			return nil, nil, fmt.Errorf("registry server error (HTTP %d): %s", resp.StatusCode, bodyPreview)
		}
		return nil, nil, fmt.Errorf("registry client error (HTTP %d): %s", resp.StatusCode, bodyPreview)
	}

	var v2Resp RubyGemsV2VersionResponse
	if err := json.Unmarshal(bodyBytes, &v2Resp); err != nil {
		return nil, metadata, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return &v2Resp, metadata, nil
}
