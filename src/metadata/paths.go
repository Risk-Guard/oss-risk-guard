package metadata

import (
	"fmt"
	"net/url"
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/common"
)

// Pattern: {outputDir}/packages/{ecosystem}/{packageName}/
func PackageBasePath(outputDir, ecosystem, packageName string) string {
	return filepath.Join(outputDir, "packages", ecosystem, url.PathEscape(packageName))
}

// Pattern: {outputDir}/source/{url-path}/
func SourceBasePath(outputDir, sourceURL string) (string, error) {
	sourcePath, err := common.GetSourcePath(sourceURL)
	if err != nil {
		return "", fmt.Errorf("failed to get source path: %w", err)
	}
	return filepath.Join(outputDir, sourcePath), nil
}
