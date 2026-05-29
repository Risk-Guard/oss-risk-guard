package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/helpers"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sarif"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	"go.uber.org/zap"
)

// extractAnalysisViolations distills a single DAG run's check outputs into
// the per-package raw violations record cached by the audit pipeline.
// DependencyPath is left nil here; the merge step is responsible for setting
// the correct depth for the current project's graph.
func extractAnalysisViolations(input dag_impl.Input, checkOutputs []checks.Output) *violations.AnalysisViolations {
	var v []violations.Violation
	for _, check := range checkOutputs {
		if check.Check.CheckStatus == storage.StatusViolation {
			v = append(v, violations.Violation{
				CheckCode: check.Check.CheckCode,
				Rationale: check.Check.Rationale,
				Evidence:  check.Check.Evidence,
			})
		}
	}
	now := time.Now()
	return &violations.AnalysisViolations{
		AnalysisID:     input.AnalysisIdentifier,
		AnalyzedAt:     &now,
		DependencyPath: nil,
		Violations:     v,
	}
}

// gradeViolations is the merge step: it folds every per-package
// AnalysisViolations (plus the local-source analysis) into one
// ViolationsResult, applies the resolved root policy, and produces the final
// graded SARIF Report. This is the only place policy touches SARIF.
func gradeViolations(ctx context.Context, sourceID string, local *violations.AnalysisViolations, deps []*violations.AnalysisViolations, policyOverrideFile, policyDefaultFile string) (*policy.EvaluationResult, error) {
	log := ctxutil.GetLogger(ctx)

	var overridePol, defaultPol *policy.CompiledPolicy
	var rawYAML string

	if policyOverrideFile != "" {
		rawBytes, err := os.ReadFile(policyOverrideFile) //nolint:gosec // path is user-provided flag
		if err != nil {
			return nil, fmt.Errorf("reading policy override file: %w", err)
		}
		rawYAML = string(rawBytes)
		loadResult, err := policy.LoadFullFromBytes(rawBytes, policyOverrideFile)
		if err != nil {
			return nil, fmt.Errorf("loading policy override: %w", err)
		}
		overridePol = loadResult.Policy
	}
	if policyDefaultFile != "" {
		rawBytes, err := os.ReadFile(policyDefaultFile) //nolint:gosec // path is user-provided flag
		if err != nil {
			return nil, fmt.Errorf("reading policy default file: %w", err)
		}
		if rawYAML == "" {
			rawYAML = string(rawBytes)
		}
		loadResult, err := policy.LoadFullFromBytes(rawBytes, policyDefaultFile)
		if err != nil {
			return nil, fmt.Errorf("loading policy default: %w", err)
		}
		defaultPol = loadResult.Policy
	}

	repoPolicy, _, _, _ := policy.GetRootPolicy(ctx)
	pol := policy.Resolve(overridePol, repoPolicy, defaultPol)

	analyses := make([]violations.AnalysisViolations, 0, 1+len(deps))
	if local != nil {
		analyses = append(analyses, *local)
	}
	for _, d := range deps {
		if d == nil {
			continue
		}
		analyses = append(analyses, *d)
	}

	combined := &violations.ViolationsResult{
		RootAnalysis: sourceID,
		Analyses:     analyses,
	}

	categoryMap := dag_builder.BuildCheckCategoryMap(localdag.Builder)
	result, err := policy.EvaluateCompiled(pol, combined, sourceID, time.Now(), categoryMap, rawYAML)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation: %w", err)
	}

	log.Info("evaluation complete",
		zap.String("status", result.Status),
		zap.Int("findings", len(result.Findings)))
	return result, nil
}

func writeEvaluationYAML(ctx context.Context, result *policy.EvaluationResult, outputFile string) error {
	log := ctxutil.GetLogger(ctx)

	if err := os.MkdirAll(filepath.Dir(outputFile), 0o750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	if err := helpers.WriteYAML(outputFile, result); err != nil {
		return fmt.Errorf("writing evaluation result: %w", err)
	}

	log.Info("wrote evaluation result", zap.String("path", outputFile))
	return nil
}

func writeSARIF(ctx context.Context, result *policy.EvaluationResult, outputFile string) error {
	log := ctxutil.GetLogger(ctx)

	if err := os.MkdirAll(filepath.Dir(outputFile), 0o750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	checkMetadata, _ := dag_builder.GetAllCheckMetadata(localdag.Builder)
	report, err := sarif.FromEvaluationResult(result, checkMetadata)
	if err != nil {
		return fmt.Errorf("converting to SARIF: %w", err)
	}

	// Guarantee every result has a physicalLocation (GitHub Code Scanning rejects
	// results that carry only a logical location, e.g. source findings).
	sarif.EnsurePhysicalLocations(report)

	if err := report.WriteFile(outputFile); err != nil {
		return fmt.Errorf("writing SARIF report: %w", err)
	}

	log.Info("wrote SARIF report", zap.String("path", outputFile))
	return nil
}
