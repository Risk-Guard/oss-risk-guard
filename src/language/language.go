package language

import (
	"context"
	"encoding/json"
	"fmt"
	"risk-guard/src/language/metadata"
	"risk-guard/src/models"
)

// ConvertToType converts data to a typed struct.
// If data is already the target type, returns it directly.
// If data is a map (from YAML deserialization), converts via JSON roundtrip.
func ConvertToType[T any](data any) (*T, error) {
	if typed, ok := data.(*T); ok {
		return typed, nil
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling data: %w", err)
	}

	var result T
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("unmarshaling to %T: %w", result, err)
	}

	return &result, nil
}

// RegistryResponse contains the parsed API response and metadata from a package registry fetch.
type RegistryResponse struct {
	// Data is the parsed response from the registry API (e.g., NPMPackageData, PyPIPackageResponse).
	Data any `json:"data,omitempty"`

	// ReleaseData holds release/version history from the full package endpoint.
	// For PyPI with a version query, Data comes from /pypi/{name}/{version}/json
	// while ReleaseData comes from /pypi/{name}/json.
	// Nil when the full endpoint already provides both (npm, pypi without version).
	ReleaseData any `json:"release_data,omitempty"`

	// StatusCode is the HTTP status code from the registry API.
	StatusCode int `json:"status_code"`

	// Headers contains selected HTTP response headers.
	Headers map[string]string `json:"headers,omitempty"`
}

type Language interface {
	FetchPackageFromRegistry(ctx context.Context, pkg models.PackageInfo) (*RegistryResponse, error)
	ExtractPackageMetadata(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.PackageMetadata, *string, *string, error)
	ExtractVersionHistory(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.VersionMetadata, error)

	// NormalizeName normalizes a package name according to ecosystem-specific rules.
	// For npm: case-sensitive (trim whitespace only)
	// For pypi: PEP 503 normalization (lowercase, [-_.] -> -)
	NormalizeName(name string) string

	// Metadata returns the static metadata for this language ecosystem
	Metadata() *metadata.Metadata

	DependencyFilePatterns() []string

	CompareVersions(a, b string) (int, error)
	ExtractPackageArchive(artifactPath, destDir string) error
	ExtractInstallScriptsFromFiles(files map[string]string) ([]string, error)
}

// EcosystemUtils defines shared utilities for ecosystem-specific operations.
// Used by consumers that only need name normalization or version comparison.
type EcosystemUtils interface {
	NormalizeName(name string) string
	CompareVersions(a, b string) (int, error)
}

func MustGetEcosystemUtils(utils map[string]EcosystemUtils, ecosystem string) EcosystemUtils {
	u, ok := utils[ecosystem]
	if !ok {
		panic(fmt.Sprintf("ecosystem utils not found for ecosystem: %q", ecosystem))
	}
	return u
}
