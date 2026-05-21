package lockfile

import (
	"os"
	"path/filepath"
	"strings"
)

type DetectorFunc func(manifestDir, repoRoot string) *string

type DetectorWithManager struct {
	Detect  DetectorFunc
	Manager string
}

func PathDepth(relPath string) int {
	parts := strings.Split(filepath.Clean(relPath), string(filepath.Separator))
	depth := 0
	for _, part := range parts {
		if part == ".." {
			depth++
		}
	}
	return depth
}

func depthFromManifest(relPath, manifestDir, repoRoot string) int {
	if strings.HasPrefix(relPath, "..") {
		return PathDepth(relPath)
	}
	absPath := filepath.Join(repoRoot, relPath)
	lockfileDir := filepath.Dir(absPath)
	rel, err := filepath.Rel(manifestDir, lockfileDir)
	if err != nil {
		return PathDepth(relPath)
	}
	return PathDepth(rel)
}

func ChooseClosestWithManager(manifestDir, repoRoot string, detectors []DetectorWithManager) (*string, *string) {
	var closest *string
	var closestManager *string
	closestDepth := -1

	for _, d := range detectors {
		if found := d.Detect(manifestDir, repoRoot); found != nil {
			depth := depthFromManifest(*found, manifestDir, repoRoot)
			if closest == nil || depth < closestDepth {
				closest = found
				closestDepth = depth
				manager := d.Manager
				closestManager = &manager
			}
		}
	}
	return closest, closestManager
}

func Detect(manifestDir, repoRoot string, lockfileNames ...string) *string {
	dir := manifestDir
	for {
		for _, name := range lockfileNames {
			lockPath := filepath.Join(dir, name)
			if _, err := os.Stat(lockPath); err == nil {
				relPath, err := filepath.Rel(repoRoot, lockPath)
				if err != nil {
					relPath = name
				}
				return &relPath
			}
		}
		if dir == repoRoot {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}
