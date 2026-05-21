package package_detector

import (
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pathutil"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"strings"
)

func enrichManifests(manifests []models.DetectedManifest, repoRootPath, sourceKey string) []models.ManifestResult {
	enriched := make([]models.ManifestResult, 0, len(manifests))

	for _, detected := range manifests {
		if len(detected.Paths) == 0 {
			enriched = append(enriched, models.ManifestResult{DetectedManifest: detected})
			continue
		}

		manifestPath := pathutil.ResolveManifestPath(detected.Paths[0], repoRootPath)
		manifestDir := filepath.Dir(manifestPath)

		lockfile, pkgManager := ecosystem.DetectLockfileWithManager(detected.Ecosystem, manifestDir, repoRootPath)
		detected.Lockfile = lockfile
		detected.PackageManager = pkgManager

		parsed, err := ecosystem.ParseManifest(detected, repoRootPath)
		if err != nil {
			errStr := err.Error()
			result := models.ManifestResult{DetectedManifest: detected}
			result.ParseError = &errStr
			enriched = append(enriched, result)
		} else if parsed != nil {
			enrichLockfileEdges(parsed, sourceKey)
			enriched = append(enriched, *parsed)
		}
	}

	return enriched
}

func buildUnversionedSourceMap(manifest *models.ManifestResult) map[string]models.LocationInfo {
	// Build map: unversioned key -> {SourceFile, LineNumber}
	depInfo := make(map[string]models.LocationInfo)
	for _, dep := range manifest.Dependencies {
		if dep.Location == nil {
			continue
		}
		depInfo[dep.AnalysisIdentifier] = models.LocationInfo{
			File:       dep.Location.File,
			LineNumber: dep.Location.LineNumber,
		}
	}
	return depInfo
}

// enrichLockfileEdges sets ParentKey=sourceKey and attaches SourceFile/LineNumber
// from manifest dependencies to direct lockfile edges (those with ParentKey=="").
func enrichLockfileEdges(manifest *models.ManifestResult, sourceKey string) {
	if len(manifest.LockfileDependencies) == 0 {
		return
	}

	depInfo := buildUnversionedSourceMap(manifest)

	for i := range manifest.LockfileDependencies {
		edge := &manifest.LockfileDependencies[i]
		if edge.ParentKey != "" {
			continue
		}

		// Set ParentKey to sourceKey for direct deps
		edge.ParentKey = sourceKey

		// Strip ?version= to get unversioned key for lookup
		unversionedKey := stripVersion(edge.ChildKey)
		if info, ok := depInfo[unversionedKey]; ok {
			edge.Location = &models.LocationInfo{
				File:       info.File,
				LineNumber: info.LineNumber,
			}
		}
	}
}

// stripVersion removes ?version=X.Y.Z from a package key.
// "package/npm/express?version=4.18.2" -> "package/npm/express"
func stripVersion(key string) string {
	if before, _, found := strings.Cut(key, "?version="); found {
		return before
	}
	return key
}
