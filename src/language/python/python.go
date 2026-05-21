package python

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/language/metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"time"

	pythonnormalize "github.com/Risk-Guard/oss-risk-guard/src/language/python/normalize"
	pypiregistry "github.com/Risk-Guard/oss-risk-guard/src/registry/pypi"

	"go.uber.org/zap"
)

type Python struct {
	client   *pypiregistry.Client
	metadata *metadata.Metadata
}

func New(meta *metadata.Metadata) *Python {
	return &Python{client: pypiregistry.NewClient(meta.Source.URL), metadata: meta}
}

func (p *Python) Metadata() *metadata.Metadata { return p.metadata }

func (p *Python) DependencyFilePatterns() []string {
	return []string{
		"**/pyproject.toml",
		"**/setup.cfg",
		"**/setup.py",
		"**/requirements.txt",
		"**/poetry.lock",
		"**/Pipfile.lock",
		"**/pdm.lock",
		"**/uv.lock",
	}
}

func (p *Python) NormalizeName(name string) string { return pythonnormalize.NormalizePyPIName(name) }

func (p *Python) FetchPackageFromRegistry(ctx context.Context, pkg models.PackageInfo) (*language.RegistryResponse, error) {
	log := ctxutil.GetLogger(ctx)
	log.Debug("fetching from PyPI", zap.String("package", pkg.Name), zap.String("version", pkg.Version))

	fetchedAt := time.Now()

	if pkg.Version != "" {
		versionResp, fetchMeta, err := p.client.FetchPackageVersionWithMetadata(pkg.Name, pkg.Version)
		if err != nil {
			return nil, fmt.Errorf("fetching PyPI package %s version %s: %w", pkg.Name, pkg.Version, err)
		}

		// Full endpoint for release history (version endpoint returns empty releases)
		fullResp, _, err := p.client.FetchPackageWithMetadata(pkg.Name)
		if err != nil {
			return nil, fmt.Errorf("fetching PyPI package %s release data: %w", pkg.Name, err)
		}

		log.Debug("fetched from PyPI (version-specific + full)",
			zap.String("package", pkg.Name),
			zap.Int("status_code", fetchMeta.StatusCode),
			zap.Duration("duration", time.Since(fetchedAt)))

		return &language.RegistryResponse{
			Data:        versionResp,
			ReleaseData: fullResp,
			StatusCode:  fetchMeta.StatusCode,
			Headers:     fetchMeta.Headers,
		}, nil
	}

	fullResp, fetchMeta, err := p.client.FetchPackageWithMetadata(pkg.Name)
	if err != nil {
		return nil, fmt.Errorf("fetching PyPI package %s: %w", pkg.Name, err)
	}

	log.Debug("fetched from PyPI",
		zap.String("package", pkg.Name),
		zap.Int("status_code", fetchMeta.StatusCode),
		zap.Duration("duration", time.Since(fetchedAt)))

	return &language.RegistryResponse{
		Data:        fullResp,
		ReleaseData: fullResp,
		StatusCode:  fetchMeta.StatusCode,
		Headers:     fetchMeta.Headers,
	}, nil
}

func (p *Python) ExtractPackageMetadata(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.PackageMetadata, *string, *string, error) {
	log := ctxutil.GetLogger(ctx)
	log.Debug("transforming PyPI data", zap.String("package", pkg.Name))

	if registryData == nil {
		now := time.Now()
		status := "package_not_found"
		statusReason := "package not found in registry"
		var version *string
		if pkg.Version != "" {
			status = "version_not_found"
			statusReason = fmt.Sprintf("requested version %s not found in registry", pkg.Version)
			version = &pkg.Version
		}
		return &models.PackageMetadata{
			Ecosystem:    "pypi",
			PackageName:  pkg.Name,
			Version:      version,
			Status:       status,
			StatusReason: &statusReason,
			CollectedAt:  &now,
		}, nil, nil, nil
	}

	pypiResp, err := language.ConvertToType[pypiregistry.PyPIPackageResponse](registryData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("converting registry data: %w", err)
	}

	info := pypiResp.Info
	version := info.Version
	sourceURL, rejectedURL, rejectionReason := p.extractSourceURL(ctx, info.ProjectURLs, pkg.Name)
	license := p.extractLicense(info)
	releaseDate, err := p.findReleaseDate(pypiResp.Releases, version)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extracting release date: %w", err)
	}
	dependencies, err := p.parseDependencies(info.RequiresDist)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing dependencies for %s: %w", pkg.Name, err)
	}
	maintainers := p.extractMaintainers(info, pypiResp.Ownership)
	distribution := p.extractDistribution(pypiResp.URLs)

	now := time.Now()
	pkgMeta := &models.PackageMetadata{
		Ecosystem:    "pypi",
		PackageName:  info.Name,
		Version:      &version,
		SourceURL:    sourceURL,
		License:      license,
		ReleaseDate:  releaseDate,
		Dependencies: dependencies,
		Maintainers:  maintainers,
		Distribution: distribution,
		Status:       "success",
		CollectedAt:  &now,
	}

	log.Debug("transformed PyPI data",
		zap.String("package", pkg.Name),
		zap.String("version", version),
		zap.Int("dependencies", len(dependencies)))

	return pkgMeta, rejectedURL, rejectionReason, nil
}

func (p *Python) ExtractVersionHistory(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.VersionMetadata, error) {
	log := ctxutil.GetLogger(ctx)
	log.Debug("transforming PyPI version data", zap.String("package", pkg.Name))

	pypiResp, err := language.ConvertToType[pypiregistry.PyPIPackageResponse](registryData)
	if err != nil {
		return nil, fmt.Errorf("converting registry data: %w", err)
	}

	versions, err := p.extractVersions(pypiResp.Releases)
	if err != nil {
		return nil, fmt.Errorf("extracting version history for %s: %w", pkg.Name, err)
	}

	now := time.Now()
	versionMeta := &models.VersionMetadata{
		Ecosystem:     "pypi",
		PackageName:   pypiResp.Info.Name,
		Versions:      versions,
		LatestVersion: resolveLatestVersion(pypiResp.Info.Version, versions),
		Status:        "success",
		CollectedAt:   &now,
	}

	log.Debug("transformed PyPI version data",
		zap.String("package", pkg.Name),
		zap.Int("version_count", len(versions)))

	return versionMeta, nil
}

func resolveLatestVersion(infoVersion string, versions []models.VersionInfo) *models.VersionInfo {
	if infoVersion != "" {
		for i := range versions {
			if versions[i].Version == infoVersion {
				return &versions[i]
			}
		}
	}
	if len(versions) > 0 {
		return &versions[0]
	}
	return nil
}
