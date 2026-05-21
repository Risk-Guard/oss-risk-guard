package archive

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"strings"

	"github.com/krolaw/zipstream"
)

func extractFromTarReader(tr *tar.Reader, patterns []string) (map[string]string, error) {
	files := make(map[string]string)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		if !matchesAnyPattern(header.Name, patterns) {
			continue
		}

		if header.Size > MaxTextFileSize {
			continue
		}

		content, err := io.ReadAll(io.LimitReader(tr, MaxTextFileSize))
		if err != nil {
			return nil, fmt.Errorf("reading file %s: %w", header.Name, err)
		}
		files[header.Name] = string(content)
	}

	return files, nil
}

func ExtractTargetFilesFromTarGzReader(r io.Reader, patterns []string) (map[string]string, error) {
	gzReader, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	return extractFromTarReader(tar.NewReader(gzReader), patterns)
}

func ExtractTargetFilesFromZipReader(r io.Reader, patterns []string) (map[string]string, error) {
	files := make(map[string]string)

	zr := zipstream.NewReader(r)

	for {
		header, err := zr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading zip stream: %w", err)
		}

		if header.FileInfo().IsDir() {
			continue
		}

		if !matchesAnyPattern(header.Name, patterns) {
			continue
		}

		if header.UncompressedSize64 > MaxTextFileSize {
			continue
		}

		content, err := io.ReadAll(io.LimitReader(zr, MaxTextFileSize))
		if err != nil {
			return nil, fmt.Errorf("reading file %s: %w", header.Name, err)
		}
		files[header.Name] = string(content)
	}

	return files, nil
}

func ExtractTargetFilesFromGemReader(r io.Reader, patterns []string) (map[string]string, error) {
	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading gem tar: %w", err)
		}

		if header.Name == "data.tar.gz" {
			return ExtractTargetFilesFromTarGzReader(tr, patterns)
		}
	}

	return make(map[string]string), nil
}

func DetectFormat(filename string) string {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return "targz"
	}
	if strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".whl") {
		return "zip"
	}
	if strings.HasSuffix(lower, ".gem") {
		return "gem"
	}
	return ""
}

func ExtractTargetFilesFromReader(r io.Reader, filename string, patterns []string) (map[string]string, error) {
	format := DetectFormat(filename)
	switch format {
	case "targz":
		return ExtractTargetFilesFromTarGzReader(r, patterns)
	case "zip":
		return ExtractTargetFilesFromZipReader(r, patterns)
	case "gem":
		return ExtractTargetFilesFromGemReader(r, patterns)
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", filename)
	}
}
