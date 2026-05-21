package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	httputil "github.com/Risk-Guard/oss-risk-guard/src/http"
)

// Client handles NPM registry API requests
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new NPM registry client with the given base URL
func NewClient(baseURL string) *Client {
	return &Client{
		httpClient: httputil.DefaultHTTPClient(),
		baseURL:    baseURL,
	}
}

// NPMMaintainer represents a maintainer from the NPM registry
type NPMMaintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// NPMPackageData represents the structure of NPM registry response
type NPMPackageData struct {
	Name        string                       `json:"name"`
	DistTags    map[string]string            `json:"dist-tags"`
	License     any                          `json:"license"`    // Can be string or object
	Repository  any                          `json:"repository"` // Can be string or object
	Time        map[string]string            `json:"time"`
	Versions    map[string]NPMVersionDetails `json:"versions"`
	Maintainers []NPMMaintainer              `json:"maintainers"`
}

// NPMUser represents a user who published a version to NPM
type NPMUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// NPMDist contains distribution information for a package version
type NPMDist struct {
	Tarball   string `json:"tarball"`
	Shasum    string `json:"shasum"`              // SHA-1 hex
	Integrity string `json:"integrity,omitempty"` // SRI format sha512-...
}

// NPMVersionDetails contains version-specific information
type NPMVersionDetails struct {
	License      any               `json:"license"`
	Dependencies map[string]string `json:"dependencies"`
	Dist         *NPMDist          `json:"dist,omitempty"`
	NpmUser      *NPMUser          `json:"_npmUser,omitempty"`
}

// FetchPackage fetches package data from NPM registry with caching
func (c *Client) FetchPackage(ctx context.Context, packageName string) (*NPMPackageData, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, packageName)

	// Use cached HTTP GET with 24-hour TTL for package metadata
	cacheOpts := &httputil.CacheOptions{
		CacheKey: filepath.Join("npm", packageName),
		MaxAge:   24 * time.Hour,
	}

	packageData, err := httputil.GetJSONCached[NPMPackageData](ctx, url, cacheOpts)
	if err != nil {
		// Check if it's a 404 error using GetStatusCodeFromError
		if statusCode, ok := httputil.GetStatusCodeFromError(err); ok && statusCode == http.StatusNotFound {
			return nil, fmt.Errorf("package not found")
		}
		return nil, fmt.Errorf("failed to fetch package: %w", err)
	}

	return packageData, nil
}

// FetchPackageWithMetadata fetches package data and returns both the response and HTTP metadata.
// Status code handling:
//   - 200: Returns (data, metadata, nil)
//   - 404: Returns (nil, metadata, nil) - package not found
//   - All other codes: Returns (nil, nil, error) with body preview
func (c *Client) FetchPackageWithMetadata(packageName string) (*NPMPackageData, *NPMFetchMetadata, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, packageName)
	fetchedAt := time.Now()

	// #nosec G107 -- URL is constructed from packageName parameter for legitimate npm API calls
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

	metadata := &NPMFetchMetadata{
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
	var npmData NPMPackageData
	if err := json.Unmarshal(bodyBytes, &npmData); err != nil {
		return nil, metadata, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return &npmData, metadata, nil
}

// GetPackageData fetches and extracts NPM package metadata
func (c *Client) GetPackageData(ctx context.Context, packageName string) (*models.Package, error) {
	packageData, err := c.FetchPackage(ctx, packageName)
	if err != nil {
		if err.Error() == "package not found" {
			return &models.Package{
				Name:         packageName,
				Ecosystem:    "npm",
				Status:       "not_found",
				Dependencies: []models.Dependency{},
			}, nil
		}
		return nil, err
	}

	// Extract version (latest)
	version, ok := packageData.DistTags["latest"]
	if !ok || version == "" {
		return nil, fmt.Errorf("no latest version found in dist-tags for %s", packageName)
	}
	versionPtr := &version

	// Extract source URL
	sourceURL := c.extractSourceURL(packageData.Repository)

	// Extract license: prefer version-specific, fall back to top-level
	rawLicense := packageData.License
	if versionData, ok := packageData.Versions[version]; ok && versionData.License != nil {
		rawLicense = versionData.License
	}
	license := c.extractLicense(rawLicense)

	// Extract release date
	releaseDate, err := c.extractReleaseDate(packageData.Time, version)
	if err != nil {
		return nil, fmt.Errorf("extracting release date for %s: %w", packageName, err)
	}

	// Extract dependencies
	dependencies, err := c.extractDependencies(packageData.Versions, version)
	if err != nil {
		return nil, fmt.Errorf("extracting dependencies for %s: %w", packageName, err)
	}

	return &models.Package{
		Name:         packageName,
		Ecosystem:    "npm",
		Version:      versionPtr,
		SourceURL:    sourceURL,
		License:      license,
		ReleaseDate:  releaseDate,
		Dependencies: dependencies,
		Status:       "ok",
	}, nil
}

// extractSourceURL extracts and normalizes the source URL from repository field
func (c *Client) extractSourceURL(repository any) *string {
	if repository == nil {
		return nil
	}

	var rawURL string

	// Handle both string and object formats
	switch repo := repository.(type) {
	case string:
		rawURL = repo
	case map[string]any:
		if url, ok := repo["url"].(string); ok {
			rawURL = url
		}
	}

	if rawURL == "" {
		return nil
	}

	// Normalize the URL
	normalized := common.NormalizeSourceURL(rawURL)
	return &normalized
}

// extractLicense extracts license string
func (c *Client) extractLicense(license any) *string {
	if license == nil {
		return nil
	}

	var licenseStr string
	switch lic := license.(type) {
	case string:
		licenseStr = lic
	case map[string]any:
		// Handle { "type": "MIT" } format
		if t, ok := lic["type"].(string); ok {
			licenseStr = t
		}
	}

	if licenseStr == "" {
		return nil
	}

	return &licenseStr
}

// extractReleaseDate extracts the release date for a specific version
func (c *Client) extractReleaseDate(timeMap map[string]string, version string) (*time.Time, error) {
	if timeMap == nil || version == "" {
		return nil, nil
	}

	dateStr, ok := timeMap[version]
	if !ok {
		return nil, nil
	}

	parsedTime, err := common.ParseRegistryTimestamp(dateStr)
	if err != nil {
		return nil, fmt.Errorf("parsing release date for version %s: %w", version, err)
	}

	return &parsedTime, nil
}

// extractDependencies extracts dependencies for a specific version
func (c *Client) extractDependencies(versions map[string]NPMVersionDetails, version string) ([]models.Dependency, error) {
	if versions == nil || version == "" {
		return []models.Dependency{}, nil
	}

	versionDetails, ok := versions[version]
	if !ok {
		return []models.Dependency{}, nil
	}

	var deps []models.Dependency
	for name, specifier := range versionDetails.Dependencies {
		if name == "" {
			return nil, fmt.Errorf("npm registry returned dependency with empty name for version %s", version)
		}
		deps = append(deps, models.Dependency{
			AnalysisIdentifier: models.MakeSimplePackageAnalysisIdentifier("npm", name),
			Specifiers:         []string{specifier},
		})
	}

	return deps, nil
}
