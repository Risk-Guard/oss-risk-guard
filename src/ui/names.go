package ui

import "strings"

// nodeDisplayNames gives friendly labels for the notable DAG nodes shown in a
// phase row, e.g. "scoring local source (fetching registry metadata)".
//
// This is user-facing copy and lives here rather than in the DAG engine, which
// has no business knowing what a human should read.
var nodeDisplayNames = map[string]string{
	"fetcher":             "fetching registry metadata",
	"package_detector":    "detecting packages",
	"git_resolve":         "resolving repository",
	"git_clone_content":   "reading source tree",
	"git_clone_metadata":  "reading git history",
	"transformer":         "processing registry data",
	"version_transformer": "resolving versions",
	"license_files":       "scanning licenses",
}

// nodeDisplayName turns a reflected node type like "*fetcher.Node" into a
// human-readable current-activity label. Unlisted nodes fall back to their
// package name with underscores spaced out.
func nodeDisplayName(nodeType string) string {
	pkg := strings.TrimPrefix(nodeType, "*")
	if i := strings.LastIndex(pkg, "."); i >= 0 {
		pkg = pkg[:i]
	}
	if name, ok := nodeDisplayNames[pkg]; ok {
		return name
	}
	return strings.ReplaceAll(pkg, "_", " ")
}
