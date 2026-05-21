package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeTarPath(t *testing.T) {
	destDir := "/tmp/extract"

	tests := []struct {
		name      string
		entryName string
		wantPath  string
		wantErr   bool
	}{
		{
			name:      "simple file",
			entryName: "package/index.js",
			wantPath:  "/tmp/extract/package/index.js",
			wantErr:   false,
		},
		{
			name:      "nested file",
			entryName: "package/lib/utils/helper.js",
			wantPath:  "/tmp/extract/package/lib/utils/helper.js",
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
		{
			name:      "dot file is fine",
			entryName: "package/.gitignore",
			wantPath:  "/tmp/extract/package/.gitignore",
			wantErr:   false,
		},
		{
			name:      "double dot in name is fine",
			entryName: "package/file..txt",
			wantPath:  "/tmp/extract/package/file..txt",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := SanitizeTarPath(tt.entryName, destDir)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantPath, gotPath)
		})
	}
}

func TestExtractTarEntry_Directory(t *testing.T) {
	destDir := t.TempDir()
	targetPath := filepath.Join(destDir, "mydir")

	header := &tar.Header{
		Name:     "mydir",
		Typeflag: tar.TypeDir,
	}

	err := ExtractTarEntry(nil, header, targetPath)
	require.NoError(t, err)

	info, err := os.Stat(targetPath)
	require.NoError(t, err)
	require.True(t, info.IsDir())
}

func TestExtractTarEntry_Symlink(t *testing.T) {
	destDir := t.TempDir()
	targetPath := filepath.Join(destDir, "link")

	header := &tar.Header{
		Name:     "link",
		Typeflag: tar.TypeSymlink,
		Linkname: "/etc/passwd",
	}

	err := ExtractTarEntry(nil, header, targetPath)
	require.NoError(t, err)

	_, err = os.Lstat(targetPath)
	require.Error(t, err, "symlinks should be silently dropped")
}

func TestExtractRegularFile(t *testing.T) {
	destDir := t.TempDir()

	content := []byte("hello world")
	buf := bytes.NewReader(content)

	header := &tar.Header{
		Name: "test.txt",
		Size: int64(len(content)),
	}

	targetPath := filepath.Join(destDir, "test.txt")
	err := ExtractRegularFile(buf, header, targetPath)
	require.NoError(t, err)

	data, err := os.ReadFile(targetPath) //nolint:gosec // test code
	require.NoError(t, err)
	require.Equal(t, content, data)
}

func TestExtractRegularFile_TooLarge(t *testing.T) {
	destDir := t.TempDir()

	header := &tar.Header{
		Name: "large.bin",
		Size: MaxFileSize + 1,
	}

	targetPath := filepath.Join(destDir, "large.bin")
	err := ExtractRegularFile(nil, header, targetPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "file too large")
}

func TestExtractRegularFile_NestedPath(t *testing.T) {
	destDir := t.TempDir()

	content := []byte("nested content")
	buf := bytes.NewReader(content)

	header := &tar.Header{
		Name: "a/b/c/test.txt",
		Size: int64(len(content)),
	}

	targetPath := filepath.Join(destDir, "a", "b", "c", "test.txt")
	err := ExtractRegularFile(buf, header, targetPath)
	require.NoError(t, err)

	data, err := os.ReadFile(targetPath) //nolint:gosec // test code
	require.NoError(t, err)
	require.Equal(t, content, data)
}

func TestExtractTarGz(t *testing.T) {
	destDir := t.TempDir()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("test file content")
	err := tw.WriteHeader(&tar.Header{
		Name: "package/test.txt",
		Mode: 0o644,
		Size: int64(len(content)),
	})
	require.NoError(t, err)
	_, err = tw.Write(content)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	tarballPath := filepath.Join(t.TempDir(), "test.tar.gz")
	require.NoError(t, os.WriteFile(tarballPath, buf.Bytes(), 0o600))

	err = ExtractTarGz(tarballPath, destDir)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(destDir, "package", "test.txt")) //nolint:gosec // test code
	require.NoError(t, err)
	require.Equal(t, content, data)
}
