package metadata

import (
	"net/url"
	"path/filepath"
)

// Pattern: {outputDir}/packages/{ecosystem}/{packageName}/
func PackageBasePath(outputDir, ecosystem, packageName string) string {
	return filepath.Join(outputDir, "packages", ecosystem, url.PathEscape(packageName))
}
