package python

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractPackageArchive_Zip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("setup.py")
	require.NoError(t, err)
	_, err = w.Write([]byte("# setup script"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "package-1.0.0.zip")
	require.NoError(t, os.WriteFile(zipPath, buf.Bytes(), 0o600))

	destDir := filepath.Join(tmpDir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o750))

	p := &Python{}
	err = p.ExtractPackageArchive(zipPath, destDir)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(destDir, "setup.py")) //nolint:gosec // test file
	require.NoError(t, err)
	require.Equal(t, "# setup script", string(content))
}

func TestExtractPackageArchive_Whl(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("package/__init__.py")
	require.NoError(t, err)
	_, err = w.Write([]byte("# init"))
	require.NoError(t, err)

	w, err = zw.Create("package-1.0.dist-info/METADATA")
	require.NoError(t, err)
	_, err = w.Write([]byte("Name: package"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	tmpDir := t.TempDir()
	whlPath := filepath.Join(tmpDir, "package-1.0-py3-none-any.whl")
	require.NoError(t, os.WriteFile(whlPath, buf.Bytes(), 0o600))

	destDir := filepath.Join(tmpDir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o750))

	p := &Python{}
	err = p.ExtractPackageArchive(whlPath, destDir)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(destDir, "package", "__init__.py")) //nolint:gosec // test file
	require.NoError(t, err)
	require.Equal(t, "# init", string(content))
}

func TestExtractPackageArchive_UnsupportedFormat(t *testing.T) {
	p := &Python{}
	err := p.ExtractPackageArchive("/tmp/package.exe", "/tmp/dest")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported PyPI artifact format")
}

func TestExtractInstallScriptsFromFiles_WithSetupPy(t *testing.T) {
	files := map[string]string{
		"package-1.0.0/setup.py": "from setuptools import setup\nsetup()",
	}

	p := &Python{}
	scripts, err := p.ExtractInstallScriptsFromFiles(files)
	require.NoError(t, err)
	require.Len(t, scripts, 1)
	require.Equal(t, "package-1.0.0/setup.py", scripts[0])
}

func TestExtractInstallScriptsFromFiles_NoSetupPy(t *testing.T) {
	files := map[string]string{
		"package/__init__.py":            "# init",
		"package-1.0.dist-info/METADATA": "Name: package",
	}

	p := &Python{}
	scripts, err := p.ExtractInstallScriptsFromFiles(files)
	require.NoError(t, err)
	require.Empty(t, scripts)
}

func TestExtractInstallScriptsFromFiles_RootSetupPy(t *testing.T) {
	files := map[string]string{
		"setup.py": "from setuptools import setup\nsetup()",
	}

	p := &Python{}
	scripts, err := p.ExtractInstallScriptsFromFiles(files)
	require.NoError(t, err)
	require.Len(t, scripts, 1)
	require.Equal(t, "setup.py", scripts[0])
}
