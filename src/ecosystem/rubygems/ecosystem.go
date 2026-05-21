package rubygems

import (
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/rubygems/package_manager/bundler"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

type ecosystem struct{}

var instance = &ecosystem{}

func Ecosystem() def.Ecosystem {
	return instance
}

func (e *ecosystem) Name() string {
	return "rubygems"
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
		bundler.Manager,
	}
}

func (e *ecosystem) DetectPackageManager(manifestDir, repoRoot string) (def.PackageManager, *string) {
	lockfilePath := bundler.DetectLockfile(manifestDir, repoRoot)
	if lockfilePath != nil {
		return bundler.Manager, lockfilePath
	}
	return nil, nil
}

func (e *ecosystem) GitSparseCheckoutFilePatterns() []string {
	return e.Definition().DependencyFilePatterns
}
