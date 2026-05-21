package environment

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear all env vars to test defaults
	clearEnvVars(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Check defaults
	if cfg.NVDAPIKey != "" {
		t.Errorf("expected NVDAPIKey to be empty, got %q", cfg.NVDAPIKey)
	}
	if cfg.GitHubToken != "" {
		t.Errorf("expected GitHubToken to be empty, got %q", cfg.GitHubToken)
	}
	if cfg.CacheBackend != "filesystem" {
		t.Errorf("expected CacheBackend to be 'filesystem', got %q", cfg.CacheBackend)
	}
	if cfg.CacheMaxAgeDays != 2 {
		t.Errorf("expected CacheMaxAgeDays to be 2, got %d", cfg.CacheMaxAgeDays)
	}
	if cfg.GoogleCloudProject != "oss-risk-guard" {
		t.Errorf("expected GoogleCloudProject to be 'oss-risk-guard', got %q", cfg.GoogleCloudProject)
	}
	if cfg.MetadataBackend != "filesystem" {
		t.Errorf("expected MetadataBackend to be 'filesystem', got %q", cfg.MetadataBackend)
	}
}

func TestLoad_CustomValues(t *testing.T) {
	cfg, err := loadWithEnv(t, map[string]string{
		"NVD_API_KEY":             "test-nvd-key",
		"GITHUB_TOKEN":            "test-github-token",
		"CACHE_BACKEND":           "filesystem",
		"HTTP_CACHE_MAX_AGE_DAYS": "7",
		"GOOGLE_CLOUD_PROJECT":    "test-project",
	})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg.NVDAPIKey != "test-nvd-key" {
		t.Errorf("expected NVDAPIKey to be 'test-nvd-key', got %q", cfg.NVDAPIKey)
	}
	if cfg.GitHubToken != "test-github-token" {
		t.Errorf("expected GitHubToken to be 'test-github-token', got %q", cfg.GitHubToken)
	}
	if cfg.CacheBackend != "filesystem" {
		t.Errorf("expected CacheBackend to be 'filesystem', got %q", cfg.CacheBackend)
	}
	if cfg.CacheMaxAgeDays != 7 {
		t.Errorf("expected CacheMaxAgeDays to be 7, got %d", cfg.CacheMaxAgeDays)
	}
	if cfg.GoogleCloudProject != "test-project" {
		t.Errorf("expected GoogleCloudProject to be 'test-project', got %q", cfg.GoogleCloudProject)
	}
}

func TestValidate_InvalidCacheBackend(t *testing.T) {
	_, err := loadWithEnv(t, map[string]string{
		"CACHE_BACKEND": "invalid-backend",
	})
	if err == nil {
		t.Fatal("expected error for invalid cache backend, got nil")
	}
	if !strings.Contains(err.Error(), "invalid CACHE_BACKEND") {
		t.Errorf("expected error message to contain 'invalid CACHE_BACKEND', got %q", err.Error())
	}
}

func TestValidate_InvalidMetadataBackend(t *testing.T) {
	_, err := loadWithEnv(t, map[string]string{
		"METADATA_BACKEND": "invalid-backend",
	})
	if err == nil {
		t.Fatal("expected error for invalid metadata backend, got nil")
	}
	if !strings.Contains(err.Error(), "invalid METADATA_BACKEND") {
		t.Errorf("expected error message to contain 'invalid METADATA_BACKEND', got %q", err.Error())
	}
}

func TestValidate_MetadataBackendGCS(t *testing.T) {
	cfg, err := loadWithEnv(t, map[string]string{
		"METADATA_BACKEND":   "gcs",
		"BACKEND_GCS_BUCKET": "test-bucket",
	})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.MetadataBackend != "gcs" {
		t.Errorf("expected MetadataBackend to be 'gcs', got %q", cfg.MetadataBackend)
	}
	if cfg.BackendGCSBucket != "test-bucket" {
		t.Errorf("expected BackendGCSBucket to be 'test-bucket', got %q", cfg.BackendGCSBucket)
	}
}

func TestValidate_NegativeCacheMaxAge(t *testing.T) {
	_, err := loadWithEnv(t, map[string]string{
		"HTTP_CACHE_MAX_AGE_DAYS": "-1",
	})
	if err == nil {
		t.Fatal("expected error for negative cache max age, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP_CACHE_MAX_AGE_DAYS") {
		t.Errorf("expected error message to contain 'HTTP_CACHE_MAX_AGE_DAYS', got %q", err.Error())
	}
}

func TestGetCacheMaxAge(t *testing.T) {
	cfg, err := loadWithEnv(t, map[string]string{
		"HTTP_CACHE_MAX_AGE_DAYS": "7",
	})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	expected := 7 * 24 * time.Hour
	if cfg.GetCacheMaxAge() != expected {
		t.Errorf("expected GetCacheMaxAge() to be %v, got %v", expected, cfg.GetCacheMaxAge())
	}
}

func TestString_RedactsSecrets(t *testing.T) {
	cfg, err := loadWithEnv(t, map[string]string{
		"NVD_API_KEY":  "secret-key",
		"GITHUB_TOKEN": "secret-token",
	})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	str := cfg.String()

	// Should not contain actual secrets
	if strings.Contains(str, "secret-key") {
		t.Error("String() should not contain actual NVD_API_KEY value")
	}
	if strings.Contains(str, "secret-token") {
		t.Error("String() should not contain actual GITHUB_TOKEN value")
	}

	// Should contain redaction markers
	if !strings.Contains(str, "<redacted>") {
		t.Error("String() should contain '<redacted>' for secrets")
	}

	// Should contain field names
	if !strings.Contains(str, "NVD_API_KEY") {
		t.Error("String() should contain 'NVD_API_KEY' field name")
	}
	if !strings.Contains(str, "GITHUB_TOKEN") {
		t.Error("String() should contain 'GITHUB_TOKEN' field name")
	}
}

func TestString_ShowsEmptySecrets(t *testing.T) {
	clearEnvVars(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	str := cfg.String()

	// Should show <empty> for empty secrets
	if !strings.Contains(str, "<empty>") {
		t.Error("String() should contain '<empty>' for empty secrets")
	}
}

func TestValidate_TokenWithTrailingNewlineIsStripped(t *testing.T) {
	cfg, err := loadWithEnv(t, map[string]string{
		"GITHUB_TOKEN": "ghp_validtoken123\n",
	})
	if err != nil {
		t.Fatalf("expected trailing newline to be stripped, got error: %v", err)
	}
	if cfg.GitHubToken != "ghp_validtoken123" {
		t.Errorf("expected token to be trimmed, got %q", cfg.GitHubToken)
	}
}

func TestValidate_TokenWithLeadingSpaceIsStripped(t *testing.T) {
	cfg, err := loadWithEnv(t, map[string]string{
		"NVD_API_KEY": " abc123",
	})
	if err != nil {
		t.Fatalf("expected leading space to be stripped, got error: %v", err)
	}
	if cfg.NVDAPIKey != "abc123" {
		t.Errorf("expected token to be trimmed, got %q", cfg.NVDAPIKey)
	}
}

func TestValidate_TokenWithEmbeddedWhitespace(t *testing.T) {
	_, err := loadWithEnv(t, map[string]string{
		"GITHUB_TOKEN": "ghp_valid\ttoken",
	})
	if err == nil {
		t.Fatal("expected error for token with embedded tab, got nil")
	}
	if !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("expected error message to mention GITHUB_TOKEN, got %q", err.Error())
	}
}

func TestValidate_CleanTokenPasses(t *testing.T) {
	_, err := loadWithEnv(t, map[string]string{
		"GITHUB_TOKEN": "ghp_validtoken123ABC-_",
		"NVD_API_KEY":  "abc-123_XYZ",
	})
	if err != nil {
		t.Fatalf("expected clean tokens to pass validation, got error: %v", err)
	}
}

// clearEnvVars clears all environment variables used by the config
func clearEnvVars(t *testing.T) {
	t.Helper()
	vars := []string{
		"NVD_API_KEY",
		"GITHUB_TOKEN",
		"CACHE_BACKEND",
		"METADATA_BACKEND",
		"HTTP_CACHE_MAX_AGE_DAYS",
		"GOOGLE_CLOUD_PROJECT",
		"BACKEND_GCS_BUCKET",
	}
	for _, v := range vars {
		if err := os.Unsetenv(v); err != nil {
			t.Fatalf("failed to unset %s: %v", v, err)
		}
	}
}

// loadWithEnv is a test helper that sets environment variables, loads config,
// and cleans up automatically. This keeps test utilities in test files only.
func loadWithEnv(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()

	// Clear all env vars first
	clearEnvVars(t)

	// Set test env vars
	for key, value := range env {
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("failed to set env var %s: %v", key, err)
		}
	}

	// Clean up after test
	t.Cleanup(func() {
		clearEnvVars(t)
	})

	return Load()
}
