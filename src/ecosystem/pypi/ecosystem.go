package pypi

import (
	"risk-guard/src/ecosystem/def"
	"risk-guard/src/ecosystem/pypi/package_manager/pdm"
	"risk-guard/src/ecosystem/pypi/package_manager/pipenv"
	"risk-guard/src/ecosystem/pypi/package_manager/poetry"
	"risk-guard/src/ecosystem/pypi/package_manager/uv"
	"risk-guard/src/models"
)

type ecosystem struct{}

var instance = &ecosystem{}

func Ecosystem() def.Ecosystem {
	return instance
}

func (e *ecosystem) Name() string {
	return "pypi"
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
		uv.Manager,
		poetry.Manager,
		pipenv.Manager,
		pdm.Manager,
	}
}

func (e *ecosystem) DetectPackageManager(manifestDir, repoRoot string) (def.PackageManager, *string) {
	lockfilePath, managerName := DetectLockfileWithManager(manifestDir, repoRoot)
	if managerName == nil {
		return nil, nil
	}
	managerMap := map[string]def.PackageManager{
		"uv":     uv.Manager,
		"poetry": poetry.Manager,
		"pipenv": pipenv.Manager,
		"pdm":    pdm.Manager,
	}
	return managerMap[*managerName], lockfilePath
}

func (e *ecosystem) GitSparseCheckoutFilePatterns() []string {
	return e.Definition().DependencyFilePatterns
}
