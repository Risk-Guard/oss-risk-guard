package archive

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func SanitizeZipPath(entryName, destDir string) (string, error) {
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

func ExtractZipFile(f *zip.File, targetPath string) error {
	if f.UncompressedSize64 > uint64(MaxFileSize) {
		return fmt.Errorf("file too large: %s (%d bytes)", f.Name, f.UncompressedSize64)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
		return fmt.Errorf("creating parent directory: %w", err)
	}

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("opening zip entry: %w", err)
	}
	defer func() { _ = rc.Close() }()

	outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640) //nolint:gosec // Path already sanitized
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer func() { _ = outFile.Close() }()

	copySize := int64(f.UncompressedSize64) //nolint:gosec // Size already validated against MaxFileSize above
	if _, err := io.CopyN(outFile, rc, copySize); err != nil {
		return fmt.Errorf("extracting file: %w", err)
	}

	return nil
}
