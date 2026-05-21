package fetcher

import (
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/language/registry"
	"github.com/Risk-Guard/oss-risk-guard/src/metadata"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func (o *Output) Summary(outputDir string) executiondag.NodeSummary {
	var filesWritten []string
	stats := map[string]any{}

	ecosystemCounts := make(map[string]int)
	for _, regOutput := range o.Outputs {
		basePath := metadata.PackageBasePath(outputDir, regOutput.Ecosystem, regOutput.Name)
		dataPath := filepath.Join(basePath, "data.json")
		requestPath := filepath.Join(basePath, "request.yml")
		filesWritten = append(filesWritten, dataPath, requestPath)
		ecosystemCounts[regOutput.Ecosystem]++
	}

	stats["packages_fetched"] = len(o.Outputs)
	if len(ecosystemCounts) > 0 {
		stats["ecosystems"] = ecosystemCounts
	}

	var dataSource *executiondag.DataSourceInfo
	if len(o.Outputs) > 0 {
		firstEcosystem := o.Outputs[0].Ecosystem
		meta := registry.MustGet(firstEcosystem)
		info := meta.Source.ToDataSourceInfo()
		dataSource = &info
	}

	return executiondag.NodeSummary{
		NodeType:     "registry_fetcher",
		Status:       string(o.GetStatus()),
		FilesWritten: filesWritten,
		Stats:        stats,
		DataSource:   dataSource,
	}
}
