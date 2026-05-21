package javascript

import (
	"github.com/Risk-Guard/oss-risk-guard/src/archive"
	"github.com/Risk-Guard/oss-risk-guard/src/language/javascript/detection"
)

func (j *JavaScript) ExtractPackageArchive(artifactPath, destDir string) error {
	return archive.ExtractTarGz(artifactPath, destDir)
}

func (j *JavaScript) ExtractInstallScriptsFromFiles(files map[string]string) ([]string, error) {
	content, ok := files["package/package.json"]
	if !ok {
		return nil, nil
	}
	return detection.ExtractInstallScriptsFromContent([]byte(content))
}
