package environment

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

var validTokenRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Config holds all validated environment variables for Risk Guard.
// This provides type-safe access to configuration with validation
// and prevents runtime errors from missing or invalid environment variables.
type Config struct {
	// API Keys (optional, increase rate limits)
	NVDAPIKey   string `env:"NVD_API_KEY" envDefault:""`
	GitHubToken string `env:"GITHUB_TOKEN" envDefault:""`

	// Cache Configuration
	CacheBackend    string `env:"CACHE_BACKEND" envDefault:"filesystem"`
	CacheMaxAgeDays int    `env:"HTTP_CACHE_MAX_AGE_DAYS" envDefault:"2"`

	MetadataBackend  string `env:"METADATA_BACKEND" envDefault:"filesystem"`
	BackendGCSBucket string `env:"BACKEND_GCS_BUCKET" envDefault:""`
	KeyPrefix        string `env:"GCS_PREFIX" envDefault:"v3"`
	HTTPGCSBucket    string `env:"HTTP_GCS_BUCKET" envDefault:""`
	HTTPGCSPrefix    string `env:"HTTP_GCS_PREFIX" envDefault:"v1"`

	ValkeyURL string `env:"VALKEY_URL" envDefault:"redis://localhost:6379"`

	// HIGH_MEM_SERVER is the URL of a high-memory server running the /artifact endpoint.
	// When set, artifact extraction is delegated to this server instead of running locally.
	// No default: the open-source CLI extracts locally; only the hosted server sets this.
	HighMemServer string `env:"HIGH_MEM_SERVER" envDefault:""`

	// HIGH_MEM_AUDIENCE is the audience for ID token authentication.
	// Defaults to "risk-guard-api" which is configured as a custom audience on the Cloud Run service.
	HighMemAudience string `env:"HIGH_MEM_AUDIENCE" envDefault:"risk-guard-api"`

	GoogleCloudProject string `env:"GOOGLE_CLOUD_PROJECT" envDefault:""`

	ScorePackageWorkflow string `env:"SCORE_PACKAGE_WORKFLOW" envDefault:""`
	ScoreSourceWorkflow  string `env:"SCORE_SOURCE_WORKFLOW" envDefault:""`
	ScoreDepsWorkflow    string `env:"SCORE_DEPS_WORKFLOW" envDefault:""`

	ServiceName string `env:"SERVICE_NAME" envDefault:"risk-guard"`

	SecureGit bool `env:"SECURE_GIT" envDefault:"false"`
}

func (c *Config) GetSecureGit() bool {
	return c.SecureGit
}

func (c *Config) GetHighMemServer() string {
	return c.HighMemServer
}

func (c *Config) GetHighMemAudience() string {
	return c.HighMemAudience
}

func (c *Config) Clone() *Config {
	return &Config{
		NVDAPIKey:            c.NVDAPIKey,
		GitHubToken:          c.GitHubToken,
		CacheBackend:         c.CacheBackend,
		CacheMaxAgeDays:      c.CacheMaxAgeDays,
		MetadataBackend:      c.MetadataBackend,
		BackendGCSBucket:     c.BackendGCSBucket,
		KeyPrefix:            c.KeyPrefix,
		HTTPGCSBucket:        c.HTTPGCSBucket,
		HTTPGCSPrefix:        c.HTTPGCSPrefix,
		ValkeyURL:            c.ValkeyURL,
		HighMemServer:        c.HighMemServer,
		HighMemAudience:      c.HighMemAudience,
		GoogleCloudProject:   c.GoogleCloudProject,
		ScorePackageWorkflow: c.ScorePackageWorkflow,
		ScoreSourceWorkflow:  c.ScoreSourceWorkflow,
		ScoreDepsWorkflow:    c.ScoreDepsWorkflow,
		ServiceName:          c.ServiceName,
		SecureGit:            c.SecureGit,
	}
}

// Load validates and returns environment configuration.
// It automatically loads .env file if present in the current directory.
// Returns an error if any validation fails.
func Load() (*Config, error) {
	// Load .env file if it exists
	// Only ignore the error if the file doesn't exist; other errors (permissions, parse errors) should fail
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load .env file: %w", err)
	}

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse environment variables: %w", err)
	}

	// Strip whitespace from tokens before validation
	cfg.GitHubToken = strings.TrimSpace(cfg.GitHubToken)
	cfg.NVDAPIKey = strings.TrimSpace(cfg.NVDAPIKey)

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks that the configuration is valid.
func (c *Config) validate() error {
	// Validate API tokens (if set)
	if err := validateToken("GITHUB_TOKEN", c.GitHubToken); err != nil {
		return err
	}
	if err := validateToken("NVD_API_KEY", c.NVDAPIKey); err != nil {
		return err
	}

	// Validate cache backend
	if c.CacheBackend != "filesystem" && c.CacheBackend != "gcs" {
		return fmt.Errorf("invalid CACHE_BACKEND: must be 'filesystem' or 'gcs', got '%s'", c.CacheBackend)
	}

	// Validate HTTP GCS bucket is set when using gcs cache backend
	if c.CacheBackend == "gcs" && c.HTTPGCSBucket == "" {
		return fmt.Errorf("HTTP_GCS_BUCKET is required when CACHE_BACKEND is 'gcs'")
	}

	// Validate metadata backend
	if c.MetadataBackend != "none" && c.MetadataBackend != "filesystem" && c.MetadataBackend != "gcs" {
		return fmt.Errorf("invalid METADATA_BACKEND: must be 'none', 'filesystem', or 'gcs', got '%s'", c.MetadataBackend)
	}

	// Validate GCS bucket is set when using gcs backend
	if c.MetadataBackend == "gcs" && c.BackendGCSBucket == "" {
		return fmt.Errorf("BACKEND_GCS_BUCKET is required when METADATA_BACKEND is 'gcs'")
	}

	// Validate GCS prefix doesn't have leading/trailing slashes
	if strings.HasPrefix(c.KeyPrefix, "/") {
		return fmt.Errorf("invalid GCS_PREFIX: must not start with '/', got '%s'", c.KeyPrefix)
	}
	if strings.HasSuffix(c.KeyPrefix, "/") {
		return fmt.Errorf("invalid GCS_PREFIX: must not end with '/', got '%s'", c.KeyPrefix)
	}

	// Validate HTTP GCS prefix doesn't have leading/trailing slashes
	if strings.HasPrefix(c.HTTPGCSPrefix, "/") {
		return fmt.Errorf("invalid HTTP_GCS_PREFIX: must not start with '/', got '%s'", c.HTTPGCSPrefix)
	}
	if strings.HasSuffix(c.HTTPGCSPrefix, "/") {
		return fmt.Errorf("invalid HTTP_GCS_PREFIX: must not end with '/', got '%s'", c.HTTPGCSPrefix)
	}

	// Validate cache max age
	if c.CacheMaxAgeDays < 0 {
		return fmt.Errorf("invalid HTTP_CACHE_MAX_AGE_DAYS: must be non-negative, got %d", c.CacheMaxAgeDays)
	}

	return nil
}

func validateToken(name, value string) error {
	if value == "" {
		return nil
	}
	if !validTokenRegex.MatchString(value) {
		return fmt.Errorf("invalid %s: contains invalid characters (must match [a-zA-Z0-9_-]+)", name)
	}
	return nil
}

// GetCacheMaxAge returns the cache max age as a time.Duration.
func (c *Config) GetCacheMaxAge() time.Duration {
	return time.Duration(c.CacheMaxAgeDays) * 24 * time.Hour
}

// String returns a string representation of the configuration with secrets redacted.
// This is safe to use in logs and error messages.
func (c *Config) String() string {
	var sb strings.Builder
	sb.WriteString("Environment Configuration:\n")
	fmt.Fprintf(&sb, "  NVD_API_KEY: %s\n", redact(c.NVDAPIKey))
	fmt.Fprintf(&sb, "  GITHUB_TOKEN: %s\n", redact(c.GitHubToken))
	fmt.Fprintf(&sb, "  CACHE_BACKEND: %s\n", c.CacheBackend)
	fmt.Fprintf(&sb, "  METADATA_BACKEND: %s\n", c.MetadataBackend)
	fmt.Fprintf(&sb, "  BACKEND_GCS_BUCKET: %s\n", c.BackendGCSBucket)
	fmt.Fprintf(&sb, "  GCS_PREFIX: %s\n", c.KeyPrefix)
	fmt.Fprintf(&sb, "  HTTP_GCS_BUCKET: %s\n", c.HTTPGCSBucket)
	fmt.Fprintf(&sb, "  HTTP_GCS_PREFIX: %s\n", c.HTTPGCSPrefix)
	fmt.Fprintf(&sb, "  HTTP_CACHE_MAX_AGE_DAYS: %d\n", c.CacheMaxAgeDays)
	fmt.Fprintf(&sb, "  GOOGLE_CLOUD_PROJECT: %s\n", c.GoogleCloudProject)
	return sb.String()
}

// redact returns a redacted version of a secret value.
// Returns "<empty>" if the value is empty, or "<redacted>" if it has a value.
func redact(secret string) string {
	if secret == "" {
		return "<empty>"
	}
	return "<redacted>"
}
