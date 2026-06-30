package main

import (
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	dagcmd "github.com/Risk-Guard/oss-risk-guard/src/cmd/subcommands/dag"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var auditPackageCmd = &cobra.Command{
	Use:   "package <package-key>",
	Short: "Score a single package by its analysis-identifier key",
	Long: `Score a single package via the local package DAG.

The argument is an analysis-identifier key produced by the sbom or 'audit deps'
commands, e.g. "package/npm/express" or "package/npm/lodash?version=4.17.20".

With --sarif the graded report is written to that path; without it a
human-readable findings summary is printed to the terminal.

No cache backend is used; every invocation runs the DAG fresh.

Examples:
  risk-guard audit package 'package/npm/express'
  risk-guard audit package 'package/npm/lodash?version=4.17.20' --sarif out.sarif`,
	Args: cobra.ExactArgs(1),
	RunE: runAuditPackage,
}

func init() {
	registerSharedDAGFlags(auditPackageCmd)
	auditPackageCmd.Flags().StringVar(&policyOverride, "policy-override", "", flagHelpPolicyOverride)
	auditPackageCmd.Flags().StringVar(&policyDefault, "policy-default", "", flagHelpPolicyDefault)
	auditPackageCmd.Flags().StringVar(&sarifOutFile, "sarif", "", flagHelpSARIF)
	registerSummaryRenderFlags(auditPackageCmd, true)
	auditCmd.AddCommand(auditPackageCmd)
}

func runAuditPackage(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	logger := ctxutil.GetLogger(ctx)

	eco, name, version, err := parsePackageKey(args[0])
	if err != nil {
		return err
	}

	// git_clone_content uses the cache backend as its on-disk clone store, so
	// it must be initialized even though `audit package` doesn't memoize results.
	ctx, err = cache.InitializeCacheBackend(ctx)
	if err != nil {
		return err
	}
	ctx, err = storage.InitializeStorageBackend(ctx)
	if err != nil {
		return err
	}

	// Apply built-in knownOverrides and any policy overrides (e.g. the @types/*
	// source-URL gap-fill) before the DAG runs, so a single-package audit
	// resolves sources the same way a repo scan does.
	ctx, overridesHash := packageOverrideContext(ctx, args[0], "")
	cmd.SetContext(ctx)

	input := dag_impl.NewPackageInputWithVersion(eco, name, version, overridesHash)

	logger.Info("auditing package",
		zap.String("ecosystem", eco),
		zap.String("package", name),
		zap.Stringp("version", version))

	resp, err := dagcmd.BuildAndRunDAG(ctx, input, localdag.PackageBuilder)
	if err != nil {
		return fmt.Errorf("scoring package: %w", err)
	}

	analysis := extractAnalysisViolations(input, resp.Checks)

	// No --sarif: grade and print a findings summary to the terminal instead of
	// requiring an output file, so a bare `audit package <key>` is useful.
	if sarifOutFile == "" {
		report, err := assembleReport(ctx, input.AnalysisIdentifier, nil, []*violations.AnalysisViolations{analysis}, nil, nil)
		if err != nil {
			return err
		}
		return renderReportSummary(report, summaryModeOverride, summaryGitHub, summaryGitLab, resolveRepoRoot(summaryRepoRoot))
	}

	result, err := gradeViolations(ctx, input.AnalysisIdentifier, nil, []*violations.AnalysisViolations{analysis}, policyOverride, policyDefault)
	if err != nil {
		return fmt.Errorf("evaluation failed: %w", err)
	}

	if err := writeSARIF(ctx, result, sarifOutFile); err != nil {
		return fmt.Errorf("sarif output failed: %w", err)
	}

	return nil
}

// parsePackageKey decodes an analysis-identifier key of the form
// "package/{eco}/{name}" or "package/{eco}/{name}?version={ver}" into its
// components. Returns nil version when the key has none.
func parsePackageKey(key string) (ecosystem, name string, version *string, err error) {
	eco, n, v := parseKeyIdentity(key)
	if eco == "" || n == "" {
		return "", "", nil, fmt.Errorf("invalid package key %q (expected \"package/<eco>/<name>[?version=...]\")", key)
	}
	if v == "" {
		return eco, n, nil, nil
	}
	return eco, n, &v, nil
}
