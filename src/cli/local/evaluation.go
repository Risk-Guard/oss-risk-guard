package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/dag-impl/policy_loader"
	"risk-guard/src/helpers"
	"risk-guard/src/lib/common/sarif"
	"risk-guard/src/lib/common/storage"
	"risk-guard/src/policy"
	"risk-guard/src/violations"
	"time"

	dag_builder "risk-guard/src/dag-builder"
	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"

	localdag "risk-guard/src/lib/local/dag"

	"go.uber.org/zap"
)

func evaluate(ctx context.Context, input dag_impl.Input, checkOutputs []checks.Output, policyOverrideFile, policyDefaultFile string) (*policy.EvaluationResult, error) {
	log := ctxutil.GetLogger(ctx)

	var policyOverride, policyDefault *policy.CompiledPolicy
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
		policyOverride = loadResult.Policy
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
		policyDefault = loadResult.Policy
	}

	repoPolicy := getRepoPolicyFromDAG(ctx)
	pol := policy.Resolve(policyOverride, repoPolicy, policyDefault)
	log.Info("resolved policy", zap.Int("rules", len(pol.Rules)))

	v := extractViolations(input, checkOutputs)
	categoryMap := dag_builder.BuildCheckCategoryMap(localdag.Builder)

	result, err := policy.EvaluateCompiled(pol, v, input.AnalysisIdentifier, time.Now(), categoryMap, rawYAML)
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

	if err := report.WriteFile(outputFile); err != nil {
		return fmt.Errorf("writing SARIF report: %w", err)
	}

	log.Info("wrote SARIF report", zap.String("path", outputFile))
	return nil
}

func getRepoPolicyFromDAG(ctx context.Context) *policy.CompiledPolicy {
	policyOut, ok := executiondag.TryGetOutput[*policy_loader.Node](ctx)
	if !ok {
		return nil
	}

	output, ok := policyOut.(*policy_loader.Output)
	if !ok {
		return nil
	}

	return output.Policy
}

func extractViolations(input dag_impl.Input, checkOutputs []checks.Output) *violations.ViolationsResult {
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
	return &violations.ViolationsResult{
		RootAnalysis: input.AnalysisIdentifier,
		Analyses: []violations.AnalysisViolations{
			{
				AnalysisID:     input.AnalysisIdentifier,
				AnalyzedAt:     &now,
				DependencyPath: nil,
				Violations:     v,
			},
		},
	}
}
