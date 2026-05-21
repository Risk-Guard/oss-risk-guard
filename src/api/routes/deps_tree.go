package routes

import (
	"github.com/Risk-Guard/oss-risk-guard/src/api/route"
	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
)

type DepsTreeSourceResponse struct {
	SourceKey string                   `json:"source_key"`
	Edges     []depsgraph.DepsTreeEdge `json:"edges"`
}

type DepsTreeSourceParams struct{}

type DepsTreeSourceQuery struct {
	Commit  *string
	Trusted *string
}

var RouteDepsTreeSource = route.Route[DepsTreeSourceParams, DepsTreeSourceQuery, DepsTreeSourceResponse]{
	Method:      "POST",
	Path:        "/v2/deps/tree/source/{url}",
	OperationID: "depsTreeSource",
	Summary:     "Get dependency tree for a source",
	Description: "Returns the dependency edge graph without timestamp population or outdated computation. Valkey-only.",
	Tags:        []string{"deps"},
}
