package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	httputil "github.com/Risk-Guard/oss-risk-guard/src/http"
)

// Client handles PyPI registry API requests
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new PyPI registry client with the given base URL
func NewClient(baseURL string) *Client {
	return &Client{
		httpClient: httputil.DefaultHTTPClient(),
		baseURL:    baseURL,
	}
}

// PyPIURL contains distribution file information
type PyPIURL struct {
	URL         string            `json:"url"`
	Filename    string            `json:"filename"`
	Digests     map[string]string `json:"digests"`     // sha256, md5, blake2b_256
	PackageType string            `json:"packagetype"` // bdist_wheel, sdist
}

// PyPIOwnershipRole represents a single role entry in PyPI's ownership data
type PyPIOwnershipRole struct {
	Role string `json:"role"`
	User string `json:"user"`
}

// PyPIOwnership represents the ownership section of a PyPI API response
type PyPIOwnership struct {
	Organization *string             `json:"organization"`
	Roles        []PyPIOwnershipRole `json:"roles"`
}

// PyPIPackageResponse is the full package endpoint: /pypi/{name}/json
type PyPIPackageResponse struct {
	Info      PyPIInfo             `json:"info"`
	Releases  map[string][]Release `json:"releases"`
	URLs      []PyPIURL            `json:"urls"`
	Ownership *PyPIOwnership       `json:"ownership,omitempty"`
}

// PyPIVersionResponse is the version-specific endpoint: /pypi/{name}/{version}/json
type PyPIVersionResponse struct {
	Info      PyPIInfo       `json:"info"`
	URLs      []PyPIURL      `json:"urls"`
	Ownership *PyPIOwnership `json:"ownership,omitempty"`
}

// PyPIInfo contains package information
type PyPIInfo struct {
	Name              string            `json:"name"`
	Version           string            `json:"version"`
	License           string            `json:"license"`
	LicenseExpression string            `json:"license_expression"` // Modern SPDX license field (PEP 639)
	ProjectURLs       map[string]string `json:"project_urls"`
	Classifiers       []string          `json:"classifiers"`
	RequiresDist      []string          `json:"requires_dist"`
	Author            string            `json:"author"`
	AuthorEmail       string            `json:"author_email"`
	Maintainer        string            `json:"maintainer"`
	MaintainerEmail   string            `json:"maintainer_email"`
}

// Release contains release-specific information
type Release struct {
	UploadTime string `json:"upload_time"`
}

// FetchPackage fetches package data from PyPI registry with caching
func (c *Client) FetchPackage(ctx context.Context, packageName string) (*PyPIPackageResponse, error) {
	url := fmt.Sprintf("%s/%s/json", c.baseURL, packageName)

	// Use cached HTTP GET with 24-hour TTL for package metadata
	cacheOpts := &httputil.CacheOptions{
		CacheKey: filepath.Join("pypi", packageName),
		MaxAge:   24 * time.Hour,
	}

	pypiResp, err := httputil.GetJSONCached[PyPIPackageResponse](ctx, url, cacheOpts)
	if err != nil {
		// Check if it's a 404 error using GetStatusCodeFromError
		if statusCode, ok := httputil.GetStatusCodeFromError(err); ok && statusCode == http.StatusNotFound {
			return nil, fmt.Errorf("package not found")
		}
		return nil, fmt.Errorf("failed to fetch package data: %w", err)
	}

	return pypiResp, nil
}

// FetchPackageWithMetadata fetches package data and returns both the response and HTTP metadata.
// Status code handling:
//   - 200: Returns (data, metadata, nil)
//   - 404: Returns (nil, metadata, nil) - package not found
//   - All other codes: Returns (nil, nil, error) with body preview
func (c *Client) FetchPackageWithMetadata(packageName string) (*PyPIPackageResponse, *PyPIFetchMetadata, error) {
	url := fmt.Sprintf("%s/%s/json", c.baseURL, packageName)
	fetchedAt := time.Now()

	// #nosec G107 -- URL is constructed from packageName parameter for legitimate PyPI API calls
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch package data: %w", err)
	}

	// Capture HTTP headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Read response body
	bodyBytes, err := httputil.ReadResponseBody(resp)
	if err != nil {
		return nil, nil, err
	}

	metadata := &PyPIFetchMetadata{
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

	// Only parse JSON for successful responses
	var pypiResp PyPIPackageResponse
	if err := json.Unmarshal(bodyBytes, &pypiResp); err != nil {
		return nil, metadata, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return &pypiResp, metadata, nil
}

// FetchPackageVersionWithMetadata fetches version-specific package data.
// Uses the /pypi/{name}/{version}/json endpoint.
func (c *Client) FetchPackageVersionWithMetadata(packageName, version string) (*PyPIVersionResponse, *PyPIFetchMetadata, error) {
	url := fmt.Sprintf("%s/%s/%s/json", c.baseURL, packageName, version)
	fetchedAt := time.Now()

	// #nosec G107 -- URL is constructed from packageName and version parameters for legitimate PyPI API calls
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

	metadata := &PyPIFetchMetadata{
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

	var pypiResp PyPIVersionResponse
	if err := json.Unmarshal(bodyBytes, &pypiResp); err != nil {
		return nil, metadata, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return &pypiResp, metadata, nil
}
