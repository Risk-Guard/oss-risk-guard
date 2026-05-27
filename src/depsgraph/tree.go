package depsgraph

import (
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
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
	// Location is the manifest file + line that declared this dep, when known.
	// Only populated for direct dependencies; transitives and the root are nil.
	Location *models.LocationInfo
}
