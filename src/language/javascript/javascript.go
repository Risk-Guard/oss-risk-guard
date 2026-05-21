package javascript

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

	npmregistry "github.com/Risk-Guard/oss-risk-guard/src/registry/npm"

	"go.uber.org/zap"
)

type JavaScript struct {
	client   *npmregistry.Client
	metadata *metadata.Metadata
}

func New(meta *metadata.Metadata) *JavaScript {
	return &JavaScript{
		client:   npmregistry.NewClient(meta.Source.URL),
		metadata: meta,
	}
}

func (j *JavaScript) Metadata() *metadata.Metadata { return j.metadata }

func (j *JavaScript) DependencyFilePatterns() []string {
	return []string{
		"**/package.json",
		"**/package-lock.json",
		"**/yarn.lock",
		"**/pnpm-lock.yaml",
		"**/bun.lock",
		"**/bun.lockb",
	}
}

func (j *JavaScript) NormalizeName(name string) string { return strings.TrimSpace(name) }

func (j *JavaScript) FetchPackageFromRegistry(ctx context.Context, pkg models.PackageInfo) (*language.RegistryResponse, error) {
	log := ctxutil.GetLogger(ctx)
	log.Debug("fetching from NPM", zap.String("package", pkg.Name), zap.String("version", pkg.Version))

	fetchedAt := time.Now()
	npmResp, fetchMeta, err := j.client.FetchPackageWithMetadata(pkg.Name)
	if err != nil {
		return nil, fmt.Errorf("fetching NPM package %s: %w", pkg.Name, err)
	}

	response := &language.RegistryResponse{
		Data:       npmResp,
		StatusCode: fetchMeta.StatusCode,
		Headers:    fetchMeta.Headers,
	}

	log.Debug("fetched from NPM",
		zap.String("package", pkg.Name),
		zap.String("version", pkg.Version),
		zap.Int("status_code", fetchMeta.StatusCode),
		zap.Duration("duration", time.Since(fetchedAt)))

	return response, nil
}

func (j *JavaScript) ExtractPackageMetadata(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.PackageMetadata, *string, *string, error) {
	log := ctxutil.GetLogger(ctx)
	log.Debug("transforming NPM data", zap.String("package", pkg.Name))

	npmResp, err := language.ConvertToType[npmregistry.NPMPackageData](registryData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("converting registry data: %w", err)
	}

	targetVersion := pkg.Version
	if targetVersion == "" {
		var ok bool
		targetVersion, ok = npmResp.DistTags["latest"]
		if !ok || targetVersion == "" {
			return nil, nil, nil, fmt.Errorf("no latest version found in dist-tags")
		}
	}

	if _, exists := npmResp.Versions[targetVersion]; !exists {
		now := time.Now()
		statusReason := fmt.Sprintf("version %s not found in registry", targetVersion)
		return &models.PackageMetadata{
			Ecosystem:    "npm",
			PackageName:  npmResp.Name,
			Version:      &targetVersion,
			Status:       "version_not_found",
			StatusReason: &statusReason,
			CollectedAt:  &now,
		}, nil, nil, nil
	}

	sourceURL, rejectedURL, rejectionReason := j.extractSourceURL(ctx, npmResp.Repository, pkg.Name)
	rawLicense := npmResp.License
	if versionData, ok := npmResp.Versions[targetVersion]; ok && versionData.License != nil {
		rawLicense = versionData.License
	}
	license := j.extractLicense(rawLicense)
	releaseDate, err := j.findReleaseDate(npmResp.Time, targetVersion)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extracting release date for %s: %w", pkg.Name, err)
	}
	dependencies, err := j.extractDependencies(npmResp.Versions, targetVersion)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extracting dependencies for %s: %w", pkg.Name, err)
	}
	maintainers, err := j.extractMaintainersWithPublishHistory(npmResp.Versions, npmResp.Time, npmResp.Maintainers)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extracting maintainers for %s: %w", pkg.Name, err)
	}
	distribution := j.extractDistribution(npmResp.Versions, targetVersion)

	now := time.Now()
	pkgMeta := &models.PackageMetadata{
		Ecosystem:    "npm",
		PackageName:  npmResp.Name,
		Version:      &targetVersion,
		SourceURL:    sourceURL,
		License:      license,
		ReleaseDate:  releaseDate,
		Dependencies: dependencies,
		Maintainers:  maintainers,
		Distribution: distribution,
		Status:       "success",
		CollectedAt:  &now,
	}

	log.Debug("transformed NPM data",
		zap.String("package", pkg.Name),
		zap.String("version", targetVersion),
		zap.Int("dependencies", len(dependencies)))

	return pkgMeta, rejectedURL, rejectionReason, nil
}

func (j *JavaScript) ExtractVersionHistory(ctx context.Context, pkg models.PackageInfo, registryData any) (*models.VersionMetadata, error) {
	log := ctxutil.GetLogger(ctx)
	log.Debug("transforming NPM version data", zap.String("package", pkg.Name))

	npmResp, err := language.ConvertToType[npmregistry.NPMPackageData](registryData)
	if err != nil {
		return nil, fmt.Errorf("converting registry data: %w", err)
	}

	versions, err := j.extractVersions(npmResp.Time, npmResp.Versions)
	if err != nil {
		return nil, fmt.Errorf("extracting version history for %s: %w", pkg.Name, err)
	}

	now := time.Now()
	versionMeta := &models.VersionMetadata{
		Ecosystem:     "npm",
		PackageName:   npmResp.Name,
		Versions:      versions,
		LatestVersion: j.resolveLatestVersion(npmResp.DistTags, versions),
		Status:        "success",
		CollectedAt:   &now,
	}

	log.Debug("transformed NPM version data",
		zap.String("package", pkg.Name),
		zap.Int("version_count", len(versions)))

	return versionMeta, nil
}

func (j *JavaScript) extractSourceURL(ctx context.Context, repository any, packageName string) (*string, *string, *string) {
	if repository == nil {
		return nil, nil, nil
	}
	var url string
	switch repo := repository.(type) {
	case string:
		url = repo
	case map[string]any:
		if urlVal, ok := repo["url"].(string); ok {
			url = urlVal
		}
	}
	if url == "" {
		return nil, nil, nil
	}
	normalized, finding, err := common.ValidateAndNormalizeURL(url)
	if err != nil {
		ctxutil.GetLogger(ctx).Warn("rejecting invalid source URL from npm package metadata",
			zap.String("package", packageName), zap.String("url", url),
			zap.String("normalized", normalized), zap.Error(err))
		reason := err.Error()
		return nil, &url, &reason
	}
	if finding != nil {
		return &normalized, &url, finding
	}
	return &normalized, nil, nil
}

func (j *JavaScript) extractLicense(license any) *string {
	if license == nil {
		return nil
	}
	var licenseStr string
	switch lic := license.(type) {
	case string:
		licenseStr = lic
	case map[string]any:
		if typeVal, ok := lic["type"].(string); ok {
			licenseStr = typeVal
		}
	}
	if licenseStr == "" {
		return nil
	}
	return &licenseStr
}

func (j *JavaScript) findReleaseDate(timeMap map[string]string, version string) (*time.Time, error) {
	if timeMap == nil {
		return nil, nil
	}
	dateStr, ok := timeMap[version]
	if !ok || dateStr == "" {
		return nil, nil
	}
	releaseTime, err := common.ParseRegistryTimestamp(dateStr)
	if err != nil {
		return nil, fmt.Errorf("parsing release date for version %s: %w", version, err)
	}
	return &releaseTime, nil
}

func (j *JavaScript) extractDependencies(versions map[string]npmregistry.NPMVersionDetails, version string) ([]models.Dependency, error) {
	versionDetails, ok := versions[version]
	if !ok || len(versionDetails.Dependencies) == 0 {
		return []models.Dependency{}, nil
	}
	deps := make([]models.Dependency, 0, len(versionDetails.Dependencies))
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

func (j *JavaScript) resolveLatestVersion(distTags map[string]string, versions []models.VersionInfo) *models.VersionInfo {
	if latest, ok := distTags["latest"]; ok {
		for i := range versions {
			if versions[i].Version == latest {
				return &versions[i]
			}
		}
	}
	if len(versions) > 0 {
		return &versions[0]
	}
	return nil
}

func (j *JavaScript) extractVersions(timeMap map[string]string, versionsMap map[string]npmregistry.NPMVersionDetails) ([]models.VersionInfo, error) {
	if len(timeMap) == 0 {
		return nil, fmt.Errorf("no version data in time map")
	}
	var versions []models.VersionInfo
	for version, dateStr := range timeMap {
		if version == "created" || version == "modified" {
			continue
		}
		if _, exists := versionsMap[version]; !exists {
			continue
		}
		parsedTime, err := common.ParseRegistryTimestamp(dateStr)
		if err != nil {
			return nil, fmt.Errorf("parsing timestamp for version %s: %w", version, err)
		}
		versions = append(versions, models.VersionInfo{Version: version, ReleasedAt: parsedTime})
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no valid versions found")
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].ReleasedAt.After(versions[j].ReleasedAt) })
	return versions, nil
}
