package python

import (
	"risk-guard/src/models"

	pypiregistry "risk-guard/src/registry/pypi"
)

func (p *Python) extractDistribution(urls []pypiregistry.PyPIURL) *models.DistributionInfo {
	if len(urls) == 0 {
		return nil
	}

	var preferred *pypiregistry.PyPIURL
	for i := range urls {
		u := &urls[i]
		if u.PackageType == "sdist" {
			preferred = u
			break
		}
		if u.PackageType == "bdist_wheel" && preferred == nil {
			preferred = u
		}
	}

	if preferred == nil {
		preferred = &urls[0]
	}

	if preferred.URL == "" {
		return nil
	}

	info := &models.DistributionInfo{
		URL:      preferred.URL,
		Filename: preferred.Filename,
	}

	if sha256, ok := preferred.Digests["sha256"]; ok && sha256 != "" {
		info.Hash = sha256
		info.HashAlgorithm = "sha256"
	}

	return info
}
