package routes

import "risk-guard/src/api/route"

type DepsOutdatedSourceResponse struct {
	SourceKey      string   `json:"source_key"`
	TotalDepsCount int      `json:"total_deps_count"`
	OutdatedCount  int      `json:"outdated_count"`
	OutdatedKeys   []string `json:"outdated_keys"`
}

type DepsOutdatedSourceParams struct{}

type DepsOutdatedSourceQuery struct {
	Commit  *string
	Trusted *string
}

var RouteDepsOutdatedSource = route.Route[DepsOutdatedSourceParams, DepsOutdatedSourceQuery, DepsOutdatedSourceResponse]{
	Method:      "POST",
	Path:        "/v2/deps/outdated/source/{url}",
	OperationID: "depsOutdatedSource",
	Summary:     "Get outdated dependency counts for a source",
	Description: "Returns counts of total and outdated dependencies without the full edge graph. Valkey-only.",
	Tags:        []string{"deps"},
}
