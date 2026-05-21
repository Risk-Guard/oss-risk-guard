package package_detection

import (
	"risk-guard/src/ecosystem/def"
	"risk-guard/src/models"
)

func DetectPackages(dir string, ecosystems []def.Ecosystem) ([]models.DetectedManifest, error) {
	var manifests []models.DetectedManifest

	for _, ecosystem := range ecosystems {
		detected, err := ecosystem.DetectManifests(dir)
		if err != nil {
			continue
		}
		manifests = append(manifests, detected...)
	}

	return manifests, nil
}
