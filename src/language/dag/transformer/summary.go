package transformer

import (
	"path/filepath"
	"risk-guard/src/metadata"

	executiondag "risk-guard/src/execution-dag"
)

// Summary implements the OutputSummary interface to provide reporting information
func (o *Output) Summary(outputDir string) executiondag.NodeSummary {
	var filesWritten []string
	stats := map[string]any{}

	// Count packages by ecosystem and collect file paths
	ecosystemCounts := make(map[string]int)
	for _, pkgOutput := range o.Outputs {
		basePath := metadata.PackageBasePath(outputDir, pkgOutput.Ecosystem, pkgOutput.Name)
		filePath := filepath.Join(basePath, "package.yml")
		filesWritten = append(filesWritten, filePath)

		ecosystemCounts[pkgOutput.Ecosystem]++
	}

	stats["packages_transformed"] = len(o.Outputs)
	if len(ecosystemCounts) > 0 {
		stats["ecosystems"] = ecosystemCounts
	}
	if len(o.RejectedSourceURLs) > 0 {
		stats["rejected_source_urls"] = len(o.RejectedSourceURLs)
	}

	// Transformer doesn't fetch from external sources - it transforms existing fetcher data
	return executiondag.NodeSummary{
		NodeType:     "registry_transformer",
		Status:       string(o.GetStatus()),
		FilesWritten: filesWritten,
		Stats:        stats,
		DataSource:   nil,
	}
}
