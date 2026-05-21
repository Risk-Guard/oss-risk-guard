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

const MaxFileSize = 100 * 1024 * 1024 // 100MB per file limit

func SanitizeTarPath(entryName, destDir string) (string, error) {
	cleanName := filepath.Clean(entryName)
	if strings.HasPrefix(cleanName, "..") || strings.Contains(cleanName, "../") {
		return "", fmt.Errorf("path traversal attempt: %s", entryName)
	}

	if filepath.IsAbs(cleanName) {
		return "", fmt.Errorf("path traversal attempt: %s", entryName)
	}

	targetPath := filepath.Join(destDir, cleanName) //nolint:gosec // Path already sanitized above
	if !strings.HasPrefix(targetPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal attempt: %s", entryName)
	}

	return targetPath, nil
}

func ExtractTarEntry(tarReader io.Reader, header *tar.Header, targetPath string) error {
	switch header.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(targetPath, 0o750); err != nil { //nolint:gosec // Path validated by SanitizeTarPath
			return fmt.Errorf("creating directory: %w", err)
		}
	case tar.TypeReg:
		if err := ExtractRegularFile(tarReader, header, targetPath); err != nil {
			return err
		}
	case tar.TypeSymlink, tar.TypeLink:
		return nil
	}
	return nil
}

func ExtractRegularFile(reader io.Reader, header *tar.Header, targetPath string) error {
	if header.Size > MaxFileSize {
		return fmt.Errorf("file too large: %s (%d bytes)", header.Name, header.Size)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil { //nolint:gosec // Path validated by SanitizeTarPath
		return fmt.Errorf("creating parent directory: %w", err)
	}

	outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640) //nolint:gosec // Path already sanitized
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer func() { _ = outFile.Close() }()

	if _, err := io.CopyN(outFile, reader, header.Size); err != nil {
		return fmt.Errorf("extracting file: %w", err)
	}

	return nil
}

func ExtractTarGz(tarballPath, destDir string) error {
	f, err := os.Open(tarballPath) //nolint:gosec // Path is from trusted output directory
	if err != nil {
		return fmt.Errorf("opening tarball: %w", err)
	}
	defer func() { _ = f.Close() }()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		cleanPath, err := SanitizeTarPath(header.Name, destDir)
		if err != nil {
			return err
		}

		if err := ExtractTarEntry(tarReader, header, cleanPath); err != nil {
			return err
		}
	}

	return nil
}
