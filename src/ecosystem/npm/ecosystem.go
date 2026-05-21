package npm

import (
	"risk-guard/src/ecosystem/def"
	"risk-guard/src/ecosystem/npm/package_manager/bun"
	innernpm "risk-guard/src/ecosystem/npm/package_manager/npm"
	"risk-guard/src/ecosystem/npm/package_manager/pnpm"
	"risk-guard/src/ecosystem/npm/package_manager/yarn"
	"risk-guard/src/models"
)

type ecosystem struct{}

var instance = &ecosystem{}

func Ecosystem() def.Ecosystem {
	return instance
}

func (e *ecosystem) Name() string {
	return "npm"
}

func (e *ecosystem) Definition() *def.Definition {
	return &Definition
}

func (e *ecosystem) DetectManifests(dir string) ([]models.DetectedManifest, error) {
	return DetectManifests(dir)
}

func (e *ecosystem) ParseManifest(manifest models.DetectedManifest, repoRoot string) (*models.ManifestResult, error) {
	return ParseManifest(manifest, repoRoot)
}

func (e *ecosystem) PackageManagers() []def.PackageManager {
	return []def.PackageManager{
		innernpm.Manager,
		yarn.Manager,
		pnpm.Manager,
		bun.Manager,
	}
}

func (e *ecosystem) DetectPackageManager(manifestDir, repoRoot string) (def.PackageManager, *string) {
	lockfilePath, managerName := DetectLockfileWithManager(manifestDir, repoRoot)
	if managerName == nil {
		return nil, nil
	}
	managerMap := map[string]def.PackageManager{
		"npm":  innernpm.Manager,
		"yarn": yarn.Manager,
		"pnpm": pnpm.Manager,
		"bun":  bun.Manager,
	}
	return managerMap[*managerName], lockfilePath
}

func (e *ecosystem) GitSparseCheckoutFilePatterns() []string {
	return e.Definition().DependencyFilePatterns
}
