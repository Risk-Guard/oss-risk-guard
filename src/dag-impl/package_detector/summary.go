package package_detector

import (
	"path/filepath"

	executiondag "risk-guard/src/execution-dag"
)

func (o *Output) Summary(outputDir string) executiondag.NodeSummary {
	var filesWritten []string
	stats := map[string]any{}

	input := o.GetInput()
	filesWritten = append(filesWritten, filepath.Join(outputDir, input.BasePath(), "packages.yml"))

	stats["packages_detected"] = len(o.DetectedManifests)

	ecosystemCounts := make(map[string]int)
	for _, m := range o.DetectedManifests {
		ecosystemCounts[m.Ecosystem]++
	}
	if len(ecosystemCounts) > 0 {
		stats["ecosystems"] = ecosystemCounts
	}

	// package_detector doesn't consult external data sources - it detects from local files
	return executiondag.NodeSummary{
		NodeType:     "package_detector",
		Status:       string(o.GetStatus()),
		FilesWritten: filesWritten,
		Stats:        stats,
		DataSource:   nil,
	}
}
