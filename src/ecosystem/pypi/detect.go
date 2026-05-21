package pypi

import (
	"io/fs"
	"os"
	"path/filepath"
	"risk-guard/src/ecosystem/pathutil"
	"risk-guard/src/models"
)

func DetectManifests(rootDir string) ([]models.DetectedManifest, error) {
	var manifests []models.DetectedManifest
	skipDirs := pathutil.MergeSkipDirsWithCommonNonSourceDirs(Definition.SkipDirectories)

	err := pathutil.WalkDirs(rootDir, skipDirs, func(dir string, _ []fs.DirEntry) error {
		dirManifests := detectManifestsInDir(dir, rootDir)
		manifests = append(manifests, dirManifests...)
		return nil
	})

	return manifests, err
}

func detectManifestsInDir(dir, rootDir string) []models.DetectedManifest {
	var manifests []models.DetectedManifest

	hasRequirements := fileExists(dir, "requirements.txt")
	hasPyproject := fileExists(dir, "pyproject.toml")
	hasSetupPy := fileExists(dir, "setup.py")
	hasSetupCfg := fileExists(dir, "setup.cfg")

	if hasRequirements {
		lockfile, pkgManager := DetectLockfileWithManager(dir, rootDir)
		if pkgManager == nil {
			pip := "pip"
			pkgManager = &pip
		}
		manifests = append(manifests, models.DetectedManifest{
			Ecosystem:      "pypi",
			PackageManager: pkgManager,
			Paths:          []string{relPath(rootDir, dir, "requirements.txt")},
			Lockfile:       lockfile,
		})
	}

	if hasPyproject || hasSetupPy || hasSetupCfg {
		lockfile, pkgManager := DetectLockfileWithManager(dir, rootDir)
		var paths []string
		if hasPyproject {
			paths = append(paths, relPath(rootDir, dir, "pyproject.toml"))
		}
		if hasSetupCfg {
			paths = append(paths, relPath(rootDir, dir, "setup.cfg"))
		}
		if hasSetupPy {
			paths = append(paths, relPath(rootDir, dir, "setup.py"))
		}
		manifests = append(manifests, models.DetectedManifest{
			Ecosystem:      "pypi",
			PackageManager: pkgManager,
			Paths:          paths,
			Lockfile:       lockfile,
		})
	}

	return manifests
}

func fileExists(dir, filename string) bool {
	_, err := os.Stat(filepath.Join(dir, filename))
	return err == nil
}

func relPath(rootDir, dir, filename string) string {
	full := filepath.Join(dir, filename)
	rel, err := filepath.Rel(rootDir, full)
	if err != nil {
		return filename
	}
	return rel
}
