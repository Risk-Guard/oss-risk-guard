package javascript

import (
	"risk-guard/src/models"
	"strings"

	npmregistry "risk-guard/src/registry/npm"
)

func (j *JavaScript) extractDistribution(versions map[string]npmregistry.NPMVersionDetails, version string) *models.DistributionInfo {
	versionDetails, ok := versions[version]
	if !ok || versionDetails.Dist == nil {
		return nil
	}

	dist := versionDetails.Dist
	if dist.Tarball == "" {
		return nil
	}

	info := &models.DistributionInfo{
		URL: dist.Tarball,
	}

	if dist.Integrity != "" && strings.HasPrefix(dist.Integrity, "sha512-") {
		info.Hash = strings.TrimPrefix(dist.Integrity, "sha512-")
		info.HashAlgorithm = "sha512"
	} else if dist.Shasum != "" {
		info.Hash = dist.Shasum
		info.HashAlgorithm = "sha1"
	}

	return info
}
