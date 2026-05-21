package violations

import (
	"risk-guard/src/models"
	"time"
)

type Violation struct {
	CheckCode string   `json:"check_code"`
	Rationale string   `json:"rationale"`
	Evidence  []string `json:"evidence,omitempty"`
}

type AnalysisViolations struct {
	AnalysisID     string               `json:"analysis_id"`
	AnalyzedAt     *time.Time           `json:"analyzed_at,omitempty"`
	DependencyPath []string             `json:"dependency_path"`
	RootLocation   *models.LocationInfo `json:"location,omitempty"`
	Dev            bool                 `json:"dev,omitempty"`
	Violations     []Violation          `json:"violations"`
}

type ViolationsResult struct {
	RootAnalysis string               `json:"root_analysis"`
	Analyses     []AnalysisViolations `json:"analyses"`
}
