package archive

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeZipPath(t *testing.T) {
	destDir := "/tmp/extract"

	tests := []struct {
		name      string
		entryName string
		wantPath  string
		wantErr   bool
	}{
		{
			name:      "simple file",
			entryName: "lib/utils.py",
			wantPath:  "/tmp/extract/lib/utils.py",
			wantErr:   false,
		},
		{
			name:      "nested file",
			entryName: "package/lib/utils/helper.py",
			wantPath:  "/tmp/extract/package/lib/utils/helper.py",
			wantErr:   false,
		},
		{
			name:      "path traversal with ..",
			entryName: "../../../etc/passwd",
			wantPath:  "",
			wantErr:   true,
		},
		{
			name:      "path traversal embedded",
			entryName: "package/../../../etc/passwd",
			wantPath:  "",
			wantErr:   true,
		},
		{
			name:      "absolute path attempt",
			entryName: "/etc/passwd",
			wantPath:  "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := SanitizeZipPath(tt.entryName, destDir)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantPath, gotPath)
		})
	}
}

func TestExtractZipFile(t *testing.T) {
	destDir := t.TempDir()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	content := []byte("hello from zip")
	w, err := zw.Create("test.txt")
	require.NoError(t, err)
	_, err = w.Write(content)
	require.NoError(t, err)

	require.NoError(t, zw.Close())

	zipPath := filepath.Join(t.TempDir(), "test.zip")
	require.NoError(t, os.WriteFile(zipPath, buf.Bytes(), 0o600))

	r, err := zip.OpenReader(zipPath)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)

	targetPath := filepath.Join(destDir, "test.txt")
	err = ExtractZipFile(r.File[0], targetPath)
	require.NoError(t, err)

	data, err := os.ReadFile(targetPath) //nolint:gosec // test code
	require.NoError(t, err)
	require.Equal(t, content, data)
}

func TestExtractZipFile_TooLarge(t *testing.T) {
	destDir := t.TempDir()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("small.bin")
	require.NoError(t, err)
	_, err = w.Write([]byte("test"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	zipPath := filepath.Join(t.TempDir(), "test.zip")
	require.NoError(t, os.WriteFile(zipPath, buf.Bytes(), 0o600))

	r, err := zip.OpenReader(zipPath)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)

	f := r.File[0]
	f.UncompressedSize64 = uint64(MaxFileSize + 1)

	targetPath := filepath.Join(destDir, "small.bin")
	err = ExtractZipFile(f, targetPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "file too large")
}

func TestExtractZipFile_NestedPath(t *testing.T) {
	destDir := t.TempDir()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	content := []byte("nested content")
	w, err := zw.Create("a/b/c/test.txt")
	require.NoError(t, err)
	_, err = w.Write(content)
	require.NoError(t, err)

	require.NoError(t, zw.Close())

	zipPath := filepath.Join(t.TempDir(), "test.zip")
	require.NoError(t, os.WriteFile(zipPath, buf.Bytes(), 0o600))

	r, err := zip.OpenReader(zipPath)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)

	targetPath := filepath.Join(destDir, "a", "b", "c", "test.txt")
	err = ExtractZipFile(r.File[0], targetPath)
	require.NoError(t, err)

	data, err := os.ReadFile(targetPath) //nolint:gosec // test code
	require.NoError(t, err)
	require.Equal(t, content, data)
}
