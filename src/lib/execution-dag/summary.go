package executiondag

// DataSourceInfo contains information about external data sources consulted by fetch nodes
type DataSourceInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

// NodeSummary contains information about what a node did during execution
type NodeSummary struct {
	NodeType     string          `json:"node_type"`               // Type name of the node
	Status       string          `json:"status"`                  // "success", "skipped", "error"
	FilesWritten []string        `json:"files_written,omitempty"` // Paths to files written by this node
	Stats        map[string]any  `json:"stats,omitempty"`         // Node-specific statistics (e.g., records fetched, items processed)
	DataSource   *DataSourceInfo `json:"data_source,omitempty"`   // Non-nil for fetch nodes that consult external sources
}

// OutputSummary is an optional interface that node outputs can implement
// to provide summary information for reporting purposes.
//
// This is primarily intended for fetch and transform node outputs.
// The Summary() method has access to the output's data to generate statistics.
// The outputDir parameter allows outputs to construct file paths they wrote.
type OutputSummary interface {
	Summary(outputDir string) NodeSummary
}
