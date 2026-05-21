package def

import "github.com/Risk-Guard/oss-risk-guard/src/models"

type Ecosystem interface {
	Name() string
	Definition() *Definition
	DetectManifests(dir string) ([]models.DetectedManifest, error)
	ParseManifest(manifest models.DetectedManifest, repoRoot string) (*models.ManifestResult, error)
	PackageManagers() []PackageManager
	DetectPackageManager(manifestDir, repoRoot string) (PackageManager, *string)
	GitSparseCheckoutFilePatterns() []string
}

type PackageManager interface {
	Name() string
	Ecosystem() string
	LockfileNames() []string
	DetectLockfile(manifestDir, repoRoot string) *string
}
