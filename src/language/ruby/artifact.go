package ruby

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"github.com/Risk-Guard/oss-risk-guard/src/archive"
	"strings"
)

func (r *Ruby) ExtractInstallScriptsFromFiles(files map[string]string) ([]string, error) {
	var extensions []string
	for path := range files {
		if strings.HasSuffix(path, "/extconf.rb") || path == "extconf.rb" {
			extensions = append(extensions, path)
		}
	}
	return extensions, nil
}

func (r *Ruby) ExtractPackageArchive(artifactPath, destDir string) error {
	f, err := os.Open(artifactPath) //nolint:gosec // Path is from trusted output directory
	if err != nil {
		return fmt.Errorf("opening gem: %w", err)
	}
	defer func() { _ = f.Close() }()

	tarReader := tar.NewReader(f)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading gem tar: %w", err)
		}

		if header.Name == "data.tar.gz" {
			return extractDataTarGz(tarReader, destDir)
		}
	}

	return fmt.Errorf("data.tar.gz not found in gem")
}

func extractDataTarGz(reader io.Reader, destDir string) error {
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("creating gzip reader for data.tar.gz: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading data.tar: %w", err)
		}

		cleanPath, err := archive.SanitizeTarPath(header.Name, destDir)
		if err != nil {
			return err
		}

		if err := archive.ExtractTarEntry(tarReader, header, cleanPath); err != nil {
			return err
		}
	}

	return nil
}
