package rubygems

import (
	"sort"
	"strings"
)

func sortManifestsByPriority(paths []string) []string {
	sorted := make([]string, len(paths))
	copy(sorted, paths)
	sort.Slice(sorted, func(i, j int) bool {
		iIsGemspec := strings.HasSuffix(sorted[i], ".gemspec")
		jIsGemspec := strings.HasSuffix(sorted[j], ".gemspec")
		if iIsGemspec != jIsGemspec {
			return iIsGemspec
		}
		return sorted[i] < sorted[j]
	})
	return sorted
}
