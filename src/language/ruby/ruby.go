package ruby

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/language/metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	rubynormalize "github.com/Risk-Guard/oss-risk-guard/src/language/ruby/normalize"
	rubygemsregistry "github.com/Risk-Guard/oss-risk-guard/src/registry/rubygems"

	"go.uber.org/zap"
)

type Ruby struct {
	client   *rubygemsregistry.Client
	metadata *metadata.Metadata
}

func New(meta *metadata.Metadata) *Ruby {
	return &Ruby{client: rubygemsregistry.NewClient(meta.Source.URL), metadata: meta}
}

func (r *Ruby) Metadata() *metadata.Metadata { return r.metadata }

func (r *Ruby) DependencyFilePatterns() []string {
	return []string{"**/Gemfile", "**/Gemfile.lock", "**/*.gemspec"}
}

func (r *Ruby) NormalizeName(name string) string { return rubynormalize.NormalizeRubyGemsName(name) }

func (r *Ruby) FetchPackageFromRegistry(ctx context.Context, pkg models.PackageInfo) (*language.RegistryResponse, error) {
	log := ctxutil.GetLogger(ctx)
	log.Debug("fetching from RubyGems", zap.String("package", pkg.Name), zap.String("version", pkg.Version))

	versions, err := r.client.FetchVersions(ctx, pkg.Name)
	if err != nil {
		return nil, fmt.Errorf("fetching versions for %s: %w", pkg.Name, err)
	}

	targetVersion := pkg.Version
	if targetVersion == "" {
		if len(versions) == 0 {
			return nil, fmt.Errorf("no versions found for package %s", pkg.Name)
		}
		targetVersion = versions[0].Number
		log.Debug("resolved latest version", zap.String("package", pkg.Name), zap.String("version", targetVersion))
	}

	fetchedAt := time.Now()
	v2Resp, fetchMeta, err := r.client.FetchPackageVersionWithMetadata(pkg.Name, targetVersion)
	if err != nil {
		return nil, fmt.Errorf("fetching RubyGems package %s version %s: %w", pkg.Name, targetVersion, err)
	}
	log.Debug("fetched from RubyGems v2 API",
		zap.String("package", pkg.Name), zap.String("version", targetVersion),
		zap.Int("status_code", fetchMeta.StatusCode), zap.Duration("duration", time.Since(fetchedAt)))

	if v2Resp != nil {
		owners, err := r.client.FetchOwners(ctx, pkg.Name)
		if err != nil {
			return nil, fmt.Errorf("fetching owners for %s: %w", pkg.Name, err)
		}
		v2Resp.Owners = owners
	}

	return &language.RegistryResponse{
		Data:        v2Resp,
		ReleaseData: versions,
		StatusCode:  fetchMeta.StatusCode,
		Headers:     fetchMeta.Headers,
	}, nil
}

func (r *Ruby) ExtractPackageMetadata(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.PackageMetadata, *string, *string, error) {
	log := ctxutil.GetLogger(ctx)
	log.Debug("transforming RubyGems data", zap.String("package", pkg.Name))

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
			Ecosystem: "rubygems", PackageName: pkg.Name, Version: version,
			Status: status, StatusReason: &statusReason, CollectedAt: &now,
		}, nil, nil, nil
	}

	v2Resp, err := language.ConvertToType[rubygemsregistry.RubyGemsV2VersionResponse](registryData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("converting registry data to v2 response: %w", err)
	}
	return r.transformV2Response(ctx, pkg, v2Resp)
}

func (r *Ruby) transformV2Response(ctx context.Context, pkg models.PackageInfo, v2Resp *rubygemsregistry.RubyGemsV2VersionResponse) (*models.PackageMetadata, *string, *string, error) {
	version := v2Resp.Version
	sourceURL, rejectedURL, rejectionReason := r.extractSourceURLFromV2(ctx, v2Resp, pkg.Name)
	license := r.extractLicenseFromV2(v2Resp)

	var releaseDate *time.Time
	if v2Resp.CreatedAt != "" {
		parsedTime, err := time.Parse(time.RFC3339, v2Resp.CreatedAt)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parsing created_at timestamp for %s version %s: %w", pkg.Name, version, err)
		}
		releaseDate = &parsedTime
	}
	dependencies, err := r.parseDependencies(v2Resp.Dependencies.Runtime)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing dependencies for %s: %w", pkg.Name, err)
	}

	distribution := r.extractDistribution(v2Resp)

	now := time.Now()
	pkgMeta := &models.PackageMetadata{
		Ecosystem:    "rubygems",
		PackageName:  v2Resp.Name,
		Version:      &version,
		SourceURL:    sourceURL,
		License:      license,
		ReleaseDate:  releaseDate,
		Dependencies: dependencies,
		Maintainers:  r.extractMaintainers(v2Resp.Owners),
		Distribution: distribution,
		Status:       "success",
		CollectedAt:  &now,
	}
	ctxutil.GetLogger(ctx).Debug("transformed RubyGems v2 data",
		zap.String("package", pkg.Name), zap.String("version", version), zap.Int("dependencies", len(dependencies)))
	return pkgMeta, rejectedURL, rejectionReason, nil
}

func (r *Ruby) ExtractVersionHistory(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.VersionMetadata, error) {
	ctxutil.GetLogger(ctx).Debug("transforming RubyGems version data", zap.String("package", pkg.Name))

	versions, err := language.ConvertToType[[]rubygemsregistry.VersionInfo](registryData)
	if err != nil {
		return nil, fmt.Errorf("converting registry data to version info for %s: %w", pkg.Name, err)
	}

	versionInfos, err := r.extractVersions(*versions)
	if err != nil {
		return nil, fmt.Errorf("extracting version information for %s: %w", pkg.Name, err)
	}
	now := time.Now()
	return &models.VersionMetadata{
		Ecosystem: "rubygems", PackageName: pkg.Name, Versions: versionInfos,
		LatestVersion: r.resolveLatestVersion(versionInfos),
		Status:        "success", CollectedAt: &now,
	}, nil
}

func (r *Ruby) validateAndNormalizeURL(ctx context.Context, rawURL, packageName, urlType string) (*string, *string, *string) {
	if rawURL == "" {
		return nil, nil, nil
	}
	normalized, finding, err := common.ValidateAndNormalizeURL(rawURL)
	if err != nil {
		ctxutil.GetLogger(ctx).Warn("rejecting invalid URL from RubyGems",
			zap.String("package", packageName), zap.String("url_type", urlType), zap.String("url", rawURL), zap.Error(err))
		reason := err.Error()
		return nil, &rawURL, &reason
	}
	if finding != nil {
		return &normalized, &rawURL, finding
	}
	return &normalized, nil, nil
}

func (r *Ruby) extractSourceURLFromV2(ctx context.Context, resp *rubygemsregistry.RubyGemsV2VersionResponse, packageName string) (*string, *string, *string) {
	if url, rej, reason := r.validateAndNormalizeURL(ctx, resp.SourceCodeURI, packageName, "source"); url != nil || rej != nil {
		return url, rej, reason
	}
	return r.validateAndNormalizeURL(ctx, resp.HomepageURI, packageName, "homepage")
}

func (r *Ruby) extractLicenseFromV2(resp *rubygemsregistry.RubyGemsV2VersionResponse) *string {
	if len(resp.Licenses) > 0 {
		license := strings.Join(resp.Licenses, ", ")
		return &license
	}
	return nil
}

func (r *Ruby) parseDependencies(deps []rubygemsregistry.APIDependency) ([]models.Dependency, error) {
	result := make([]models.Dependency, 0, len(deps))
	for _, dep := range deps {
		if dep.Name == "" {
			return nil, fmt.Errorf("rubygems registry returned dependency with empty name")
		}
		result = append(result, models.Dependency{
			AnalysisIdentifier: models.MakeSimplePackageAnalysisIdentifier("rubygems", dep.Name),
			Specifiers:         []string{dep.Requirements},
		})
	}
	return result, nil
}

func (r *Ruby) extractMaintainers(owners []rubygemsregistry.RubyGemsOwner) []models.Maintainer {
	if len(owners) == 0 {
		return nil
	}

	maintainers := make([]models.Maintainer, 0, len(owners))
	isActive := true
	for _, o := range owners {
		maintainers = append(maintainers, models.Maintainer{
			Name:     o.Handle,
			Email:    o.Email,
			Role:     "owner",
			IsActive: &isActive,
		})
	}
	return maintainers
}

func (r *Ruby) extractVersions(versions []rubygemsregistry.VersionInfo) ([]models.VersionInfo, error) {
	result := make([]models.VersionInfo, 0, len(versions))

	for _, v := range versions {
		if v.Prerelease {
			continue
		}

		timeStr := v.CreatedAt
		if timeStr == "" {
			timeStr = v.BuiltAt
		}

		parsedTime, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			return nil, fmt.Errorf("parsing timestamp for version %s: %w", v.Number, err)
		}

		result = append(result, models.VersionInfo{
			Version:    v.Number,
			ReleasedAt: parsedTime,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ReleasedAt.After(result[j].ReleasedAt)
	})

	return result, nil
}

func (r *Ruby) resolveLatestVersion(versions []models.VersionInfo) *models.VersionInfo {
	if len(versions) == 0 {
		return nil
	}
	best := -1
	for i := range len(versions) {
		if best == -1 {
			if _, err := r.CompareVersions(versions[i].Version, versions[i].Version); err == nil {
				best = i
			}
			continue
		}
		cmp, err := r.CompareVersions(versions[i].Version, versions[best].Version)
		if err != nil {
			continue
		}
		if cmp > 0 {
			best = i
		}
	}
	if best == -1 {
		return &versions[0]
	}
	return &versions[best]
}

func (r *Ruby) extractDistribution(v2Resp *rubygemsregistry.RubyGemsV2VersionResponse) *models.DistributionInfo {
	if v2Resp == nil || v2Resp.GemURI == "" {
		return nil
	}

	info := &models.DistributionInfo{
		URL: v2Resp.GemURI,
	}

	if v2Resp.SHA != "" {
		info.Hash = v2Resp.SHA
		info.HashAlgorithm = "sha256"
	}

	return info
}
