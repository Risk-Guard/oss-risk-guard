package python

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"risk-guard/src/archive"
	"strings"
)

func (p *Python) ExtractInstallScriptsFromFiles(files map[string]string) ([]string, error) {
	var scripts []string
	for path := range files {
		if strings.HasSuffix(path, "/setup.py") || path == "setup.py" {
			scripts = append(scripts, path)
		}
	}
	return scripts, nil
}

func (p *Python) ExtractPackageArchive(artifactPath, destDir string) error {
	lower := strings.ToLower(artifactPath)
	switch {
	case strings.HasSuffix(lower, ".whl"), strings.HasSuffix(lower, ".zip"):
		return extractZipArchive(artifactPath, destDir)
	case strings.HasSuffix(lower, ".tar.gz"):
		return archive.ExtractTarGz(artifactPath, destDir)
	default:
		return fmt.Errorf("unsupported PyPI artifact format: %s", filepath.Base(artifactPath))
	}
}

func extractZipArchive(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("opening zip archive: %w", err)
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		targetPath, err := archive.SanitizeZipPath(f.Name, destDir)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o750); err != nil {
				return fmt.Errorf("creating directory: %w", err)
			}
			continue
		}

		if err := archive.ExtractZipFile(f, targetPath); err != nil {
			return err
		}
	}

	return nil
}
