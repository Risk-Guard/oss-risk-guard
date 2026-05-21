package pypi

import (
	"path/filepath"
	"sort"
)

var manifestPriority = map[string]int{
	"pyproject.toml":   0,
	"setup.cfg":        1,
	"setup.py":         2,
	"requirements.txt": 3,
}

func sortManifestsByPriority(paths []string) []string {
	sorted := make([]string, len(paths))
	copy(sorted, paths)
	sort.Slice(sorted, func(i, j int) bool {
		pi := manifestPriority[filepath.Base(sorted[i])]
		pj := manifestPriority[filepath.Base(sorted[j])]
		return pi < pj
	})
	return sorted
}
