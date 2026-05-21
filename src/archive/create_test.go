package archive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateTarGz_RoundTrip(t *testing.T) {
	srcDir := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "root.txt"), []byte("root"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "subdir", "nested.txt"), []byte("nested"), 0o600))

	tarPath := filepath.Join(t.TempDir(), "test.tar.gz")
	require.NoError(t, CreateTarGz(srcDir, tarPath))

	info, err := os.Stat(tarPath)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))

	extractDir := t.TempDir()
	require.NoError(t, ExtractTarGz(tarPath, extractDir))

	data, err := os.ReadFile(filepath.Join(extractDir, "root.txt")) //nolint:gosec // test code
	require.NoError(t, err)
	require.Equal(t, "root", string(data))

	data, err = os.ReadFile(filepath.Join(extractDir, "subdir", "nested.txt")) //nolint:gosec // test code
	require.NoError(t, err)
	require.Equal(t, "nested", string(data))
}

func TestCreateTarGz_EmptyDir(t *testing.T) {
	srcDir := t.TempDir()
	tarPath := filepath.Join(t.TempDir(), "empty.tar.gz")

	require.NoError(t, CreateTarGz(srcDir, tarPath))

	info, err := os.Stat(tarPath)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}

func TestCreateTarGz_SkipsSymlinks(t *testing.T) {
	srcDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "real.txt"), []byte("real"), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(srcDir, "real.txt"), filepath.Join(srcDir, "link.txt")))

	tarPath := filepath.Join(t.TempDir(), "symlink.tar.gz")
	require.NoError(t, CreateTarGz(srcDir, tarPath))

	extractDir := t.TempDir()
	require.NoError(t, ExtractTarGz(tarPath, extractDir))

	_, err := os.Stat(filepath.Join(extractDir, "real.txt"))
	require.NoError(t, err)

	_, err = os.Lstat(filepath.Join(extractDir, "link.txt"))
	require.Error(t, err, "symlink should not be in archive")
}
