package npm

import (
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/lockfile"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/npm/package_manager/bun"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/npm/package_manager/pnpm"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/npm/package_manager/yarn"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pathutil"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	innernpm "github.com/Risk-Guard/oss-risk-guard/src/ecosystem/npm/package_manager/npm"
)

func DetectManifests(dir string) ([]models.DetectedManifest, error) {
	skipDirs := pathutil.MergeSkipDirsWithCommonNonSourceDirs(Definition.SkipDirectories)
	packageJSONPaths, err := innernpm.FindPackageJSONFiles(dir, skipDirs)
	if err != nil {
		return nil, err
	}

	var manifests []models.DetectedManifest

	for _, path := range packageJSONPaths {
		relPath, err := filepath.Rel(dir, path)
		if err != nil || relPath == "" {
			relPath = filepath.Base(path)
		}

		manifestDir := filepath.Dir(path)
		lockfilePath, packageManager := DetectLockfileWithManager(manifestDir, dir)

		manifests = append(manifests, models.DetectedManifest{
			Ecosystem:      "npm",
			PackageManager: packageManager,
			Paths:          []string{relPath},
			Lockfile:       lockfilePath,
		})
	}

	return manifests, nil
}

func DetectLockfileWithManager(manifestDir, repoRoot string) (*string, *string) {
	return lockfile.ChooseClosestWithManager(manifestDir, repoRoot, []lockfile.DetectorWithManager{
		{Detect: innernpm.DetectLockfile, Manager: "npm"},
		{Detect: yarn.DetectLockfile, Manager: "yarn"},
		{Detect: pnpm.DetectLockfile, Manager: "pnpm"},
		{Detect: bun.DetectLockfile, Manager: "bun"},
	})
}
