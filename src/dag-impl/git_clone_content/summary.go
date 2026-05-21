package git_clone_content

import executiondag "risk-guard/src/execution-dag"

func (o *Output) Summary(outputDir string) executiondag.NodeSummary {
	var filesWritten []string
	stats := map[string]any{}
	var dataSource *executiondag.DataSourceInfo

	if o.GetInput().HasSourceURL() {
		sourceURL := *o.GetInput().SourceURL
		dataSource = &executiondag.DataSourceInfo{
			Name:        "Git Repository",
			Description: "Source code repository",
			URL:         sourceURL,
		}

		if o.RepoPath != "" {
			filesWritten = append(filesWritten, o.RepoPath)
			stats["repo_path"] = o.RepoPath
		}
	}

	return executiondag.NodeSummary{
		NodeType:     "git_clone_content",
		Status:       string(o.GetStatus()),
		FilesWritten: filesWritten,
		Stats:        stats,
		DataSource:   dataSource,
	}
}
