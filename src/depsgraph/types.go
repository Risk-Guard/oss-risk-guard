package depsgraph

import (
	"risk-guard/src/models"
	"risk-guard/src/types"
	"time"
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

func MakeKey(ecosystem, name string) string {
	return "package/" + ecosystem + "/" + name
}
