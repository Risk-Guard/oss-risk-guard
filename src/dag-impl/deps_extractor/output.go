package deps_extractor

import (
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

type DepsProvenance string

const (
	DepsFromSource  DepsProvenance = "source"
	DepsFromPackage DepsProvenance = "package"
)

type Output struct {
	dag_impl.BaseOutput `json:",inline"`
	DepsSource          DepsProvenance        `json:"deps_source"`
	SourceFreeDeps      []models.Dependency   `json:"source_free_deps"`
	SourceLockfileEdges []models.DepsTreeEdge `json:"source_lockfile_edges"`
	PackageFreeDeps     []models.Dependency   `json:"package_free_deps"`
}

func NewOutput(status executiondag.Status, statusReason string, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(status, statusReason, input),
	}
}

func (o *Output) PersistKey() string { return "dependencies" }
