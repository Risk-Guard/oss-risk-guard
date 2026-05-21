package archive

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CreateTarGz creates a gzip-compressed tar archive from sourceDir at destPath.
// Symlinks and non-regular files are skipped for consistency with ExtractTarGz.
// Entry names are relative to sourceDir.
func CreateTarGz(sourceDir, destPath string) error {
	absSource, err := filepath.Abs(sourceDir)
	if err != nil {
		return fmt.Errorf("resolving source dir: %w", err)
	}

	outFile, err := os.Create(destPath) //nolint:gosec // destPath is from trusted internal path
	if err != nil {
		return fmt.Errorf("creating tar.gz: %w", err)
	}
	defer func() { _ = outFile.Close() }()

	gzWriter := gzip.NewWriter(outFile)
	tw := tar.NewWriter(gzWriter)

	walkErr := filepath.WalkDir(absSource, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip symlinks and non-regular files
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("getting file info: %w", err)
		}

		relPath, err := filepath.Rel(absSource, path)
		if err != nil {
			return fmt.Errorf("computing relative path: %w", err)
		}
		if relPath == "." {
			return nil
		}

		// Use forward slashes in tar entries
		relPath = strings.ReplaceAll(relPath, string(filepath.Separator), "/")

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("creating tar header: %w", err)
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("writing tar header: %w", err)
		}

		if d.IsDir() {
			return nil
		}

		f, err := os.Open(path) //nolint:gosec // path comes from WalkDir of trusted sourceDir
		if err != nil {
			return fmt.Errorf("opening file: %w", err)
		}
		defer func() { _ = f.Close() }()

		if _, err := io.Copy(tw, f); err != nil {
			return fmt.Errorf("writing file to tar: %w", err)
		}

		return nil
	})
	if walkErr != nil {
		_ = tw.Close()
		_ = gzWriter.Close()
		return walkErr
	}

	if err := tw.Close(); err != nil {
		_ = gzWriter.Close()
		return fmt.Errorf("finalizing tar: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("finalizing gzip: %w", err)
	}
	return nil
}
