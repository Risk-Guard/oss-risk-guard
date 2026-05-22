package depsgraph

import (
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/types"
)

type DepsTreeEdge struct {
	models.DepsTreeEdge
	ChildAnalyzedAt *time.Time `json:"analyzed_at,omitempty"`
}

type PathInfo = types.PathInfo

type DepsNode struct {
	ParentKey  string
	Deps       []models.Dependency
	AnalyzedAt *time.Time
}
