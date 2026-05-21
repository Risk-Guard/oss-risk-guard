package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/stretchr/testify/require"
)

func buildTarGzBuffer(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		})
		require.NoError(t, err)
		_, err = tw.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return &buf
}

func buildZipBuffer(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for name, content := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, zw.Close())
	return &buf
}

func buildGemBuffer(t *testing.T, dataFiles map[string]string) *bytes.Buffer {
	t.Helper()

	dataTarGz := buildTarGzBuffer(t, dataFiles)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	err := tw.WriteHeader(&tar.Header{
		Name: "data.tar.gz",
		Mode: 0o644,
		Size: int64(dataTarGz.Len()),
	})
	require.NoError(t, err)
	_, err = tw.Write(dataTarGz.Bytes())
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	return &buf
}

func TestExtractTargetFilesFromTarGzReader(t *testing.T) {
	buf := buildTarGzBuffer(t, map[string]string{
		"package/package.json": `{"name": "test"}`,
		"package/index.js":     `console.log("hello");`,
		"package/README.md":    `# Test`,
	})

	result, err := ExtractTargetFilesFromTarGzReader(buf, []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `{"name": "test"}`, result["package/package.json"])
}

func TestExtractTargetFilesFromTarGzReader_GlobPattern(t *testing.T) {
	buf := buildTarGzBuffer(t, map[string]string{
		"torch-2.0.0/setup.py": `from setuptools import setup`,
		"torch-2.0.0/README":   `Torch`,
	})

	result, err := ExtractTargetFilesFromTarGzReader(buf, []string{"**/setup.py"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `from setuptools import setup`, result["torch-2.0.0/setup.py"])
}

func TestExtractTargetFilesFromTarGzReader_SkipsLargeFiles(t *testing.T) {
	largeContent := make([]byte, MaxTextFileSize+1)
	for i := range largeContent {
		largeContent[i] = 'x'
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	err := tw.WriteHeader(&tar.Header{
		Name: "package/package.json",
		Mode: 0o644,
		Size: int64(len(largeContent)),
	})
	require.NoError(t, err)
	_, err = tw.Write(largeContent)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	result, err := ExtractTargetFilesFromTarGzReader(&buf, []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 0)
}

func TestExtractTargetFilesFromZipReader(t *testing.T) {
	buf := buildZipBuffer(t, map[string]string{
		"package/package.json": `{"name": "test"}`,
		"package/index.js":     `console.log("hello");`,
	})

	result, err := ExtractTargetFilesFromZipReader(buf, []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `{"name": "test"}`, result["package/package.json"])
}

func TestExtractTargetFilesFromZipReader_GlobPattern(t *testing.T) {
	buf := buildZipBuffer(t, map[string]string{
		"torch-2.0.0/setup.py": `from setuptools import setup`,
		"torch-2.0.0/README":   `Torch`,
	})

	result, err := ExtractTargetFilesFromZipReader(buf, []string{"**/setup.py"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `from setuptools import setup`, result["torch-2.0.0/setup.py"])
}

func TestExtractTargetFilesFromGemReader(t *testing.T) {
	buf := buildGemBuffer(t, map[string]string{
		"lib/extconf.rb": `require 'mkmf'`,
		"README.md":      `# Gem`,
	})

	result, err := ExtractTargetFilesFromGemReader(buf, []string{"**/extconf.rb"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `require 'mkmf'`, result["lib/extconf.rb"])
}

func TestExtractTargetFilesFromGemReader_NoDataTarGz(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	content := "metadata"
	err := tw.WriteHeader(&tar.Header{
		Name: "metadata.gz",
		Mode: 0o644,
		Size: int64(len(content)),
	})
	require.NoError(t, err)
	_, err = tw.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	result, err := ExtractTargetFilesFromGemReader(&buf, []string{"**/extconf.rb"})
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"express-4.18.2.tgz", "targz"},
		{"express-4.18.2.tar.gz", "targz"},
		{"Express-4.18.2.TAR.GZ", "targz"},
		{"torch-2.0.0.whl", "zip"},
		{"torch-2.0.0.zip", "zip"},
		{"rails-7.0.gem", "gem"},
		{"unknown.rar", ""},
		{"noextension", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			require.Equal(t, tt.want, DetectFormat(tt.filename))
		})
	}
}

func TestExtractTargetFilesFromReader_TarGz(t *testing.T) {
	buf := buildTarGzBuffer(t, map[string]string{
		"package/package.json": `{"name": "test"}`,
	})

	result, err := ExtractTargetFilesFromReader(buf, "express-4.18.2.tgz", []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `{"name": "test"}`, result["package/package.json"])
}

func TestExtractTargetFilesFromReader_Zip(t *testing.T) {
	buf := buildZipBuffer(t, map[string]string{
		"setup.py": `from setuptools import setup`,
	})

	result, err := ExtractTargetFilesFromReader(buf, "torch-2.0.0.whl", []string{"**/setup.py"})
	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestExtractTargetFilesFromReader_Gem(t *testing.T) {
	buf := buildGemBuffer(t, map[string]string{
		"lib/extconf.rb": `require 'mkmf'`,
	})

	result, err := ExtractTargetFilesFromReader(buf, "rails-7.0.gem", []string{"**/extconf.rb"})
	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestExtractTargetFilesFromReader_UnsupportedFormat(t *testing.T) {
	_, err := ExtractTargetFilesFromReader(bytes.NewReader([]byte("data")), "test.rar", []string{"*"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported archive format")
}
