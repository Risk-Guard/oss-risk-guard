package depsgraph

import (
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/violations"
)

type SBOMNode struct {
	Key            string
	Deps           []string
	AnalyzedAt     *time.Time
	Ecosystem      *string
	PackageName    *string
	PackageVersion *string
	Violations     []violations.Violation
}
