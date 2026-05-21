package depsgraph

import (
	"risk-guard/src/violations"
	"time"
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
