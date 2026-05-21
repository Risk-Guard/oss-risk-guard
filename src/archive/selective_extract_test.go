package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		pattern string
		want    bool
	}{
		{
			name:    "exact match",
			path:    "package/package.json",
			pattern: "package/package.json",
			want:    true,
		},
		{
			name:    "glob suffix match",
			path:    "torch-2.0.0/setup.py",
			pattern: "**/setup.py",
			want:    true,
		},
		{
			name:    "glob nested match",
			path:    "some/deep/nested/setup.py",
			pattern: "**/setup.py",
			want:    true,
		},
		{
			name:    "no match",
			path:    "package/index.js",
			pattern: "package/package.json",
			want:    false,
		},
		{
			name:    "glob no match",
			path:    "package/setup.py.bak",
			pattern: "**/setup.py",
			want:    false,
		},
		{
			name:    "top level glob match",
			path:    "setup.py",
			pattern: "**/setup.py",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPattern(tt.path, tt.pattern)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMatchesAnyPattern(t *testing.T) {
	patterns := []string{"package/package.json", "**/setup.py"}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "matches first pattern",
			path: "package/package.json",
			want: true,
		},
		{
			name: "matches second pattern",
			path: "torch-2.0.0/setup.py",
			want: true,
		},
		{
			name: "matches neither",
			path: "README.md",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesAnyPattern(tt.path, patterns)
			require.Equal(t, tt.want, got)
		})
	}
}

func writeTarGzFile(t *testing.T, dir, name string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for fname, content := range files {
		err := tw.WriteHeader(&tar.Header{
			Name: fname,
			Mode: 0o644,
			Size: int64(len(content)),
		})
		require.NoError(t, err)
		_, err = tw.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	return path
}

func writeZipFile(t *testing.T, dir, name string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path) //nolint:gosec // test code
	require.NoError(t, err)

	zw := zip.NewWriter(f)
	for fname, content := range files {
		w, err := zw.Create(fname)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())
	return path
}

func TestExtractTargetFiles_TarGz_ExactMatch(t *testing.T) {
	path := writeTarGzFile(t, t.TempDir(), "test.tar.gz", map[string]string{
		"package/package.json": `{"name": "test"}`,
		"package/index.js":     `console.log("hello");`,
		"package/README.md":    `# Test`,
	})

	result, err := ExtractTargetFiles(path, []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `{"name": "test"}`, result["package/package.json"])
}

func TestExtractTargetFiles_TarGz_GlobPattern(t *testing.T) {
	path := writeTarGzFile(t, t.TempDir(), "test.tar.gz", map[string]string{
		"torch-2.0.0/setup.py": `from setuptools import setup`,
		"torch-2.0.0/README":   `Torch`,
	})

	result, err := ExtractTargetFiles(path, []string{"**/setup.py"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `from setuptools import setup`, result["torch-2.0.0/setup.py"])
}

func TestExtractTargetFiles_TarGz_SkipsLargeFiles(t *testing.T) {
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

	path := filepath.Join(t.TempDir(), "test.tar.gz")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))

	result, err := ExtractTargetFiles(path, []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 0)
}

func TestExtractTargetFiles_Zip_ExactMatch(t *testing.T) {
	path := writeZipFile(t, t.TempDir(), "test.zip", map[string]string{
		"package/package.json": `{"name": "test"}`,
		"package/index.js":     `console.log("hello");`,
	})

	result, err := ExtractTargetFiles(path, []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `{"name": "test"}`, result["package/package.json"])
}

func TestExtractTargetFiles_Zip_GlobPattern(t *testing.T) {
	path := writeZipFile(t, t.TempDir(), "test.whl", map[string]string{
		"torch-2.0.0/setup.py": `from setuptools import setup`,
		"torch-2.0.0/README":   `Torch`,
	})

	result, err := ExtractTargetFiles(path, []string{"**/setup.py"})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, `from setuptools import setup`, result["torch-2.0.0/setup.py"])
}

func TestExtractTargetFiles_TarGz(t *testing.T) {
	path := writeTarGzFile(t, t.TempDir(), "test.tar.gz", map[string]string{
		"package/package.json": `{"name": "test"}`,
	})

	result, err := ExtractTargetFiles(path, []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestExtractTargetFiles_Tgz(t *testing.T) {
	path := writeTarGzFile(t, t.TempDir(), "test.tgz", map[string]string{
		"package/package.json": `{"name": "test"}`,
	})

	result, err := ExtractTargetFiles(path, []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestExtractTargetFiles_Zip(t *testing.T) {
	path := writeZipFile(t, t.TempDir(), "test.zip", map[string]string{
		"package/package.json": `{"name": "test"}`,
	})

	result, err := ExtractTargetFiles(path, []string{"package/package.json"})
	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestExtractTargetFiles_Whl(t *testing.T) {
	path := writeZipFile(t, t.TempDir(), "test.whl", map[string]string{
		"setup.py": `from setuptools import setup`,
	})

	result, err := ExtractTargetFiles(path, []string{"**/setup.py"})
	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestExtractTargetFiles_UnsupportedFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.rar")
	require.NoError(t, os.WriteFile(path, []byte("test"), 0o600))

	_, err := ExtractTargetFiles(path, []string{"**/setup.py"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported archive format")
}
