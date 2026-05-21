package unsupported

import (
	"io/fs"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pathutil"
)

// DetectedManifest represents an unsupported manifest file found in the repository.
type DetectedManifest struct {
	ManifestInfo
	FilePath string // absolute path to the file
	RelPath  string // relative path from repo root
}

// SkipDirectories returns directories that should be skipped during detection.
func SkipDirectories() []string {
	return pathutil.MergeSkipDirsWithCommonNonSourceDirs([]string{
		"node_modules",
		"vendor",
		"__pycache__",
		".venv",
		"venv",
		".tox",
		"tmp",
		".git",
		"dist",
		"build",
		"target",
	})
}

// DetectUnsupportedManifests walks the repository and finds all unsupported manifest files.
func DetectUnsupportedManifests(rootDir string) ([]DetectedManifest, error) {
	var detected []DetectedManifest

	err := pathutil.WalkDirs(rootDir, SkipDirectories(), func(dir string, entries []fs.DirEntry) error {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			manifestInfo := FindManifestInfo(e.Name())
			if manifestInfo == nil {
				continue
			}
			fullPath := filepath.Join(dir, e.Name())
			relPath, err := filepath.Rel(rootDir, fullPath)
			if err != nil {
				relPath = fullPath
			}
			detected = append(detected, DetectedManifest{
				ManifestInfo: *manifestInfo,
				FilePath:     fullPath,
				RelPath:      relPath,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return detected, nil
}
