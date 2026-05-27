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
	// Location is the manifest file + line that declared this dep, populated
	// from parsers that record source positions (npm/yarn/pnpm/bun
	// package.json, pip requirements.txt, ruby Gemfile, etc.).
	//
	// Only set on nodes that the parser-built dep tree treats as direct (edge
	// from rootKey). Transitives and the root are nil. Lockfile-resolved
	// versioned keys (e.g. "package/npm/lodash?version=4.17.20") are also nil
	// even when logically direct: locations come from the manifest, not the
	// lockfile, so they attach to the unversioned key the parser produced.
	Location *models.LocationInfo
}
