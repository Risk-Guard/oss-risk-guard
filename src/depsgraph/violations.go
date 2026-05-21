package depsgraph

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"
)

func GetViolations(ctx context.Context, backend storage.ChecksBackend, pathMap map[string]PathInfo, analysisIDs []string) (*violations.ViolationsResult, error) {
	if len(analysisIDs) == 0 {
		return &violations.ViolationsResult{
			Analyses: []violations.AnalysisViolations{},
		}, nil
	}

	rows, err := backend.GetBatch(ctx, analysisIDs)
	if err != nil {
		return nil, fmt.Errorf("fetching checks batch: %w", err)
	}

	result := &violations.ViolationsResult{
		Analyses: []violations.AnalysisViolations{},
	}

	for _, row := range rows {
		analysis := violations.AnalysisViolations{
			AnalysisID: row.Checks.AnalysisIdentifier,
			AnalyzedAt: row.Checks.AnalyzedAt,
			Violations: []violations.Violation{},
		}

		if pathMap != nil {
			if pathInfo, ok := pathMap[row.Checks.AnalysisIdentifier]; ok {
				analysis.DependencyPath = pathInfo.Path
				analysis.RootLocation = pathInfo.RootLocation
				analysis.Dev = pathInfo.Dev
			}
		}

		v := extractViolationsFromChecks(row.Checks.Checks)
		analysis.Violations = v

		result.Analyses = append(result.Analyses, analysis)
	}

	return result, nil
}

func extractViolationsFromChecks(checks []storage.Check) []violations.Violation {
	var result []violations.Violation
	for _, check := range checks {
		if check.CheckStatus == storage.StatusViolation {
			result = append(result, violations.Violation{
				CheckCode: check.CheckCode,
				Rationale: check.Rationale,
				Evidence:  check.Evidence,
			})
		}
	}
	return result
}
