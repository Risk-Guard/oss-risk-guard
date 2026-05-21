package license_files

import (
	"path/filepath"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func (o *Output) Summary(outputDir string) executiondag.NodeSummary {
	var filesWritten []string
	stats := map[string]any{}

	input := o.GetInput()
	filesWritten = append(filesWritten, filepath.Join(outputDir, input.BasePath(), "license_files.yml"))

	stats["license_files_found"] = len(o.Files)

	return executiondag.NodeSummary{
		NodeType:     "license_files",
		Status:       string(o.GetStatus()),
		FilesWritten: filesWritten,
		Stats:        stats,
		DataSource:   nil,
	}
}
