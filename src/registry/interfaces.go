package registry

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/language/metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

type EcosystemRegistryFetcher interface {
	FetchPackageFromRegistry(ctx context.Context, pkg models.PackageInfo) (*language.RegistryResponse, error)
	Metadata() *metadata.Metadata
}

type PackageMetadataExtractor interface {
	ExtractPackageMetadata(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.PackageMetadata, *string, *string, error)
	Metadata() *metadata.Metadata
}

type VersionHistoryExtractor interface {
	ExtractVersionHistory(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.VersionMetadata, error)
	Metadata() *metadata.Metadata
}

type PackageArchiveExtractor interface {
	ExtractPackageArchive(artifactPath, destDir string) error
	Metadata() *metadata.Metadata
}

type ArtifactInstallScriptExtractor interface {
	ExtractInstallScriptsFromFiles(files map[string]string) ([]string, error)
	Metadata() *metadata.Metadata
}

func MustGetFetcher(fetchers map[string]EcosystemRegistryFetcher, ecosystem string) EcosystemRegistryFetcher {
	f, ok := fetchers[ecosystem]
	if !ok {
		panic(fmt.Sprintf("no fetcher for ecosystem: %q", ecosystem))
	}
	return f
}

func MustGetMetadataExtractor(extractors map[string]PackageMetadataExtractor, ecosystem string) PackageMetadataExtractor {
	e, ok := extractors[ecosystem]
	if !ok {
		panic(fmt.Sprintf("no metadata extractor for ecosystem: %q", ecosystem))
	}
	return e
}

func MustGetVersionHistoryExtractor(extractors map[string]VersionHistoryExtractor, ecosystem string) VersionHistoryExtractor {
	e, ok := extractors[ecosystem]
	if !ok {
		panic(fmt.Sprintf("no version history extractor for ecosystem: %q", ecosystem))
	}
	return e
}

func MustGetArchiveExtractor(extractors map[string]PackageArchiveExtractor, ecosystem string) PackageArchiveExtractor {
	e, ok := extractors[ecosystem]
	if !ok {
		panic(fmt.Sprintf("no archive extractor for ecosystem: %q", ecosystem))
	}
	return e
}
