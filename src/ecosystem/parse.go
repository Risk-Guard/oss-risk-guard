package ecosystem

import (
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

func ParseManifest(manifest models.DetectedManifest, repoRoot string) (*models.ManifestResult, error) {
	eco, err := def.Get(manifest.Ecosystem)
	if err != nil {
		return nil, err
	}
	return eco.ParseManifest(manifest, repoRoot)
}
