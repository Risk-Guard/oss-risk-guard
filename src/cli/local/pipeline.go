package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	commonsarif "github.com/Risk-Guard/oss-risk-guard/src/lib/common/sarif"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	dagcmd "github.com/Risk-Guard/oss-risk-guard/src/cmd/subcommands/dag"

	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// setupAuditContext factors out the cache + storage backend init and
// overrides-load sequence that runAll, runAudit, and runScoreLocal all
// repeat. Returns the augmented ctx (also written back to cmd via
// cmd.SetContext) and the overrides hash for use by package Inputs.
func setupAuditContext(cmd *cobra.Command) (context.Context, string, error) {
	ctx := cmd.Context()
	ctx, err := cache.InitializeCacheBackend(ctx)
	if err != nil {
		return nil, "", err
	}
	ctx, err = storage.InitializeStorageBackend(ctx)
	if err != nil {
		return nil, "", err
	}
	ctx, overridesHash, err := loadAndSetupOverrides(ctx, overridesFile)
	if err != nil {
		return nil, "", err
	}
	cmd.SetContext(ctx)
	return ctx, overridesHash, nil
}

// keysAndLocations splits a sbom.DirectDep slice into the parallel arrays the
// audit pipeline needs. Direct deps with no Location are kept in the keys
// slice but absent from the map (caller treats missing entries as no-op).
func keysAndLocations(deps []sbom.DirectDep) ([]string, map[string]*models.LocationInfo) {
	keys := make([]string, len(deps))
	byKey := make(map[string]*models.LocationInfo, len(deps))
	for i, d := range deps {
		keys[i] = d.Key
		if d.Location != nil {
			byKey[d.Key] = d.Location
		}
	}
	return keys, byKey
}

// runPackageAudits owns the per-batch audit progress UI: cache config probe,
// "Auditing N direct dependencies (jobs=K)…" header, cache header line,
// scoreAll call, totals line, "M packages failed to score" line, cache hit
// summary. Returns the Run slice; an empty keys slice returns nil cleanly
// after printing a short "no direct dependencies to audit" notice.
func runPackageAudits(ctx context.Context, keys []string, locByKey map[string]*models.LocationInfo, overridesHash string) ([]*sarif.Run, error) {
	if len(keys) == 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("no direct dependencies to audit"))
		return nil, nil
	}

	logger := ctxutil.GetLogger(ctx)
	checkMetadata, _ := dag_builder.GetAllCheckMetadata(localdag.PackageBuilder)
	cacheCfg, err := buildCacheConfig(ctx, checkMetadata)
	if err != nil {
		return nil, fmt.Errorf("building audit cache config: %w", err)
	}

	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "Auditing %d direct dependencies (jobs=%d)…\n", len(keys), auditJobs)
	if cacheCfg.enabled {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("cache: %s (max-age %s)", cacheCfg.dir, cacheCfg.maxAge))
	} else {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("cache: disabled"))
	}

	logger.Info("auditing direct dependencies",
		zap.Int("count", len(keys)),
		zap.Int("jobs", auditJobs))

	runs, totals, err := scoreAll(ctx, keys, overridesHash, checkMetadata, auditJobs, cacheCfg, locByKey)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "  %s  %s  %s  %s\n",
		color.RedString("%d errors", totals.errors),
		color.YellowString("%d warnings", totals.warnings),
		color.CyanString("%d notes", totals.notes),
		color.HiBlackString("%d info", totals.info))
	if totals.audit > 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", color.RedString("%d packages failed to score", totals.audit))
	}
	if cacheCfg.enabled {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("%d/%d packages served from cache", totals.cached, len(runs)))
	}
	return runs, nil
}

// assembleReport builds a SARIF 2.1.0 Report with localRun (optional, may be
// nil) followed by auditRuns in order. No I/O.
func assembleReport(localRun *sarif.Run, auditRuns []*sarif.Run) (*sarif.Report, error) {
	report, err := sarif.New(sarif.Version210, true)
	if err != nil {
		return nil, fmt.Errorf("creating SARIF report: %w", err)
	}
	if localRun != nil {
		report.AddRun(localRun)
	}
	for _, r := range auditRuns {
		report.AddRun(r)
	}
	return report, nil
}

// writeReport persists report to outPath (mkdir-p of parent dir) and prints
// the "Wrote N runs to <path>" line to stderr. outPath must be non-empty.
func writeReport(report *sarif.Report, outPath string) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		return fmt.Errorf("creating SARIF output directory: %w", err)
	}
	if err := report.WriteFile(outPath); err != nil {
		return fmt.Errorf("writing SARIF: %w", err)
	}
	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "\nWrote %d runs to %s\n", len(report.Runs), outPath)
	return nil
}

// softFailLocalOnly handles the runAll continue-on-error branches that occur
// after the local-source Run has been built but before audit can proceed.
// When runAllContinueOnError is false, returns a wrapped fatal error; otherwise
// logs the failure, prints a yellow stderr line, and emits a local-only report.
func softFailLocalOnly(outPath string, localRun *sarif.Run, step string, cause error, logger *zap.Logger) error {
	if !runAllContinueOnError {
		return fmt.Errorf("%s: %w", step, cause)
	}
	logger.Warn(step+" failed; continuing with local-only report", zap.Error(cause))
	fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("%s failed: %v", step, cause))
	report, err := assembleReport(localRun, nil)
	if err != nil {
		return err
	}
	return writeReport(report, outPath)
}

// persistSBOM writes a generated SBOM payload to disk when --sbom-out is set.
// Honors runAllContinueOnError: returns a fatal error only if writing fails
// and continue-on-error is disabled.
func persistSBOM(path string, sbomBytes []byte, logger *zap.Logger) error {
	if err := writeSBOMOutput(path, sbomBytes); err != nil {
		if !runAllContinueOnError {
			return err
		}
		logger.Warn("persisting SBOM failed", zap.String("path", path), zap.Error(err))
		return nil
	}
	logger.Info("wrote SBOM", zap.String("path", path), zap.String("format", runAllSBOMFormat))
	return nil
}

// scoreLocalSourceRun runs the source DAG + policy evaluation + SARIF
// conversion and returns the single sarif.Run for the local repo. The Run is
// stamped with AutomationDetails.ID = "local-source" if not already set so it
// is identifiable when merged into a report alongside per-package Runs.
func scoreLocalSourceRun(ctx context.Context, repoPath, overridesHash string) (*sarif.Run, error) {
	input := dag_impl.NewSourceInputWithOverrides(repoPath, nil, false, overridesHash)

	dagResponse, err := dagcmd.BuildAndRunDAG(ctx, input, localdag.Builder)
	if err != nil {
		return nil, fmt.Errorf("DAG execution: %w", err)
	}

	po := policyOverride
	if po == "" {
		po = policyFile
	}
	result, err := evaluate(ctx, input, dagResponse.Checks, po, policyDefault)
	if err != nil {
		return nil, fmt.Errorf("evaluation: %w", err)
	}

	checkMetadata, _ := dag_builder.GetAllCheckMetadata(localdag.Builder)
	report, err := commonsarif.FromEvaluationResult(result, checkMetadata)
	if err != nil {
		return nil, fmt.Errorf("sarif conversion: %w", err)
	}
	if len(report.Runs) == 0 {
		return nil, fmt.Errorf("sarif conversion produced no runs")
	}
	run := report.Runs[0]
	if run.AutomationDetails == nil {
		run.WithAutomationDetails(sarif.NewRunAutomationDetails().WithID("local-source"))
	}
	return run, nil
}
