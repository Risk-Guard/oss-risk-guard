package npm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	"go.uber.org/zap"

	httputil "github.com/Risk-Guard/oss-risk-guard/src/http"
	httpCache "github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
)

// setupTestContext creates a context with logger and cache backend for testing
func setupTestContext(t *testing.T) context.Context {
	ctx := context.Background()
	logger := zap.NewNop()
	ctx = ctxutil.SetLogger(ctx, logger)

	// Set default test environment config
	cfg := &environment.Config{
		CacheBackend:    "filesystem",
		CacheMaxAgeDays: 1,
	}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = runpath.SetCacheDir(ctx, t.TempDir())

	backend := httpCache.NewFilesystemBackend(runpath.GetNetworkCacheDir(ctx))
	ctx = httpCache.SetCacheBackend(ctx, backend)

	testRetryOpts := httputil.BuildRetryOptions(ctx, "", 3, 100*time.Millisecond, 1*time.Second)
	ctx = httputil.SetRetryOptions(ctx, testRetryOpts)

	return ctx
}

// TestFetchPackage_NotFound tests 404 handling
func TestFetchPackage_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte(`{"error": "Not found"}`)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	ctx := setupTestContext(t)
	_, err := client.FetchPackage(ctx, "nonexistent")

	if err == nil {
		t.Fatal("Expected error but got none")
	}
	if !strings.Contains(err.Error(), "package not found") {
		t.Errorf("Expected error containing %q, got: %v", "package not found", err)
	}
}

// TestFetchPackage_ServerError tests 500 error handling
func TestFetchPackage_ServerError(t *testing.T) {
	errorBody := `{"error": "Internal server error - database connection failed"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(errorBody)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	ctx := setupTestContext(t)
	_, err := client.FetchPackage(ctx, "test-package")

	if err == nil {
		t.Fatal("Expected error for 500 response")
	}

	// TEST: Error should include response body for debugging
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Error should mention status code 500, got: %v", err)
	}

	// Error MUST include the actual error message from API
	if !strings.Contains(err.Error(), "database connection") {
		t.Errorf("FAIL: Error should include API response body for debugging. Got: %v", err)
	}
}

// TestFetchPackage_RateLimited tests 429 rate limit handling
func TestFetchPackage_RateLimited(t *testing.T) {
	rateLimitBody := `{"error": "Too many requests - rate limit exceeded"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1640000000")
		w.WriteHeader(http.StatusTooManyRequests)
		if _, err := w.Write([]byte(rateLimitBody)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	ctx := setupTestContext(t)
	_, err := client.FetchPackage(ctx, "test-package")

	if err == nil {
		t.Fatal("Expected error for 429 response")
	}

	// Should indicate rate limiting in error message
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("Error should mention status code 429, got: %v", err)
	}

	// Ideally, would include rate limit details
	t.Logf("Rate limit error: %v", err)
}

// TestFetchPackage_Success tests successful package fetch
func TestFetchPackage_Success(t *testing.T) {
	responseBody := `{
		"name": "test-package",
		"dist-tags": {
			"latest": "1.0.0"
		},
		"license": "MIT",
		"repository": {
			"type": "git",
			"url": "https://github.com/test/test"
		},
		"time": {
			"1.0.0": "2024-01-01T00:00:00.000Z"
		},
		"versions": {
			"1.0.0": {
				"license": "MIT",
				"dependencies": {
					"lodash": "^4.17.0"
				}
			}
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(responseBody)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	ctx := setupTestContext(t)
	pkg, err := client.FetchPackage(ctx, "test-package")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if pkg == nil {
		t.Fatal("Expected package data, got nil")
		return
	}

	if pkg.Name != "test-package" {
		t.Errorf("Expected name 'test-package', got '%s'", pkg.Name)
	}

	if pkg.DistTags["latest"] != "1.0.0" {
		t.Errorf("Expected latest version '1.0.0', got '%s'", pkg.DistTags["latest"])
	}
}

// TestFetchPackage_MalformedJSON tests handling of invalid JSON response
func TestFetchPackage_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{invalid json`)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	ctx := setupTestContext(t)
	_, err := client.FetchPackage(ctx, "test-package")

	if err == nil {
		t.Fatal("Expected error but got none")
	}
	if !strings.Contains(err.Error(), "failed to parse JSON") {
		t.Errorf("Expected error containing %q, got: %v", "failed to parse JSON", err)
	}
}

// TestFetchPackage_NetworkError tests network failure handling
func TestFetchPackage_NetworkError(t *testing.T) {
	client := &Client{
		httpClient: &http.Client{},
		baseURL:    "http://localhost:99999", // Invalid port
	}

	ctx := setupTestContext(t)
	_, err := client.FetchPackage(ctx, "test-package")

	if err == nil {
		t.Fatal("Expected error for network failure")
	}

	if !strings.Contains(err.Error(), "failed to fetch package") {
		t.Errorf("Expected 'failed to fetch package' error, got: %v", err)
	}
}

func TestFetchPackageWithMetadata_HTTPErrors(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		responseBody  string
		expectedInErr []string
	}{
		{
			name:          "server error 500",
			statusCode:    http.StatusInternalServerError,
			responseBody:  `{"error": "Database connection failed"}`,
			expectedInErr: []string{"500", "Database connection"},
		},
		{
			name:          "service unavailable 503",
			statusCode:    http.StatusServiceUnavailable,
			responseBody:  `{"error": "Service temporarily unavailable"}`,
			expectedInErr: []string{"503"},
		},
		{
			name:          "unauthorized 401",
			statusCode:    http.StatusUnauthorized,
			responseBody:  `{"error": "Authentication required"}`,
			expectedInErr: []string{"401", "client error"},
		},
		{
			name:          "forbidden 403",
			statusCode:    http.StatusForbidden,
			responseBody:  `{"error": "Access denied"}`,
			expectedInErr: []string{"403"},
		},
		{
			name:          "rate limited 429",
			statusCode:    http.StatusTooManyRequests,
			responseBody:  `{"error": "Rate limit exceeded"}`,
			expectedInErr: []string{"429"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if _, err := w.Write([]byte(tt.responseBody)); err != nil {
					t.Errorf("Failed to write response body: %v", err)
				}
			}))
			defer server.Close()

			client := NewClient(server.URL)
			resp, metadata, err := client.FetchPackageWithMetadata("test-package")

			if err == nil {
				t.Fatalf("Expected error for %d response, got nil", tt.statusCode)
			}
			for _, expected := range tt.expectedInErr {
				if !strings.Contains(err.Error(), expected) {
					t.Errorf("Error should contain %q, got: %v", expected, err)
				}
			}

			if resp != nil {
				t.Error("Expected nil response for error status")
			}
			if metadata != nil {
				t.Error("Expected nil metadata for error status")
			}
		})
	}
}

func TestFetchPackageWithMetadata_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte(`{"error": "Not Found"}`)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	resp, metadata, err := client.FetchPackageWithMetadata("nonexistent")
	if err != nil {
		t.Fatalf("Expected no error for 404, got: %v", err)
	}
	if metadata == nil {
		t.Fatal("Expected metadata for 404")
	}
	if metadata.StatusCode != 404 {
		t.Errorf("Expected status 404, got %d", metadata.StatusCode)
	}
	if resp != nil {
		t.Error("Expected nil response for 404")
	}
}

// TestFetchPackage_VersionLevelRepository verifies the packument's per-version
// repository field is deserialized into NPMVersionDetails, even when the
// top-level repository (hoisted from latest) is null.
func TestFetchPackage_VersionLevelRepository(t *testing.T) {
	responseBody := `{
		"name": "@types/json5",
		"dist-tags": { "latest": "2.2.0" },
		"repository": null,
		"versions": {
			"0.0.29": {
				"license": "MIT",
				"dependencies": {},
				"repository": { "type": "git", "url": "https://www.github.com/DefinitelyTyped/DefinitelyTyped.git" }
			},
			"2.2.0": {
				"license": "MIT",
				"dependencies": {}
			}
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(responseBody)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	resp, _, err := client.FetchPackageWithMetadata("@types/json5")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}

	if resp.Repository != nil {
		t.Errorf("Expected top-level repository nil, got %v", resp.Repository)
	}

	vd, ok := resp.Versions["0.0.29"]
	if !ok {
		t.Fatal("Expected version 0.0.29 in versions map")
	}
	repo, ok := vd.Repository.(map[string]any)
	if !ok {
		t.Fatalf("Expected version repository to be an object, got %T", vd.Repository)
	}
	if repo["url"] != "https://www.github.com/DefinitelyTyped/DefinitelyTyped.git" {
		t.Errorf("Unexpected version repository url: %v", repo["url"])
	}

	if vd2 := resp.Versions["2.2.0"]; vd2.Repository != nil {
		t.Errorf("Expected stub version 2.2.0 repository nil, got %v", vd2.Repository)
	}
}

func TestGetPackageData_LicenseFromVersionMetadata(t *testing.T) {
	responseBody := `{
		"name": "text-table",
		"dist-tags": { "latest": "0.2.0" },
		"license": null,
		"repository": { "type": "git", "url": "https://github.com/substack/text-table" },
		"time": { "0.2.0": "2024-01-01T00:00:00.000Z" },
		"versions": {
			"0.2.0": {
				"license": "MIT",
				"dependencies": {}
			}
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(responseBody)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	ctx := setupTestContext(t)
	pkg, err := client.GetPackageData(ctx, "text-table")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if pkg.License == nil {
		t.Fatal("Expected license to be extracted from version metadata, got nil")
	}
	if *pkg.License != "MIT" {
		t.Errorf("Expected license 'MIT', got '%s'", *pkg.License)
	}
}
