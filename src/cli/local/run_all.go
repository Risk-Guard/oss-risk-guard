package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	commonsarif "github.com/Risk-Guard/oss-risk-guard/src/lib/common/sarif"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	dagcmd "github.com/Risk-Guard/oss-risk-guard/src/cmd/subcommands/dag"

	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const defaultUnifiedSARIF = "./risk-guard-report.sarif"

var (
	runAllSBOMFormat      string
	runAllSBOMOut         string
	runAllContinueOnError bool
)

// runAll is the unified pipeline: score the local source repo, build an SBOM
// in memory, audit its direct dependencies, and emit one merged SARIF report
// containing the local-source Run plus one Run per audited package.
func runAll(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	logger := ctxutil.GetLogger(ctx)

	repoPath, err := git.ValidateGitRepo(args[0])
	if err != nil {
		return fmt.Errorf("invalid git repository: %w", err)
	}

	if auditJobs < 1 {
		return fmt.Errorf("--jobs must be >= 1")
	}

	ctx, err = cache.InitializeCacheBackend(ctx)
	if err != nil {
		return err
	}
	ctx, err = storage.InitializeStorageBackend(ctx)
	if err != nil {
		return err
	}

	ctx, overridesHash, err := loadAndSetupOverrides(ctx, overridesFile)
	if err != nil {
		return err
	}
	cmd.SetContext(ctx)

	outPath := sarifOutFile
	if outPath == "" {
		outPath = defaultUnifiedSARIF
	}

	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "Scoring local source: %s\n", repoPath)

	localRun, err := scoreLocalSourceRun(ctx, repoPath, overridesHash)
	if err != nil {
		return fmt.Errorf("scoring local source: %w", err)
	}

	bold(os.Stderr, "Building SBOM (%s)…\n", runAllSBOMFormat)
	sbomBytes, err := buildSBOMBytes(ctx, repoPath, runAllSBOMFormat)
	if err != nil {
		if !runAllContinueOnError {
			return fmt.Errorf("building SBOM: %w", err)
		}
		logger.Warn("SBOM build failed; continuing with local-only report", zap.Error(err))
		fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("SBOM build failed: %v", err))
		return writeMergedReport(outPath, localRun, nil)
	}

	if runAllSBOMOut != "" {
		if err := writeSBOMOutput(runAllSBOMOut, sbomBytes); err != nil {
			if !runAllContinueOnError {
				return err
			}
			logger.Warn("persisting SBOM failed", zap.String("path", runAllSBOMOut), zap.Error(err))
		} else {
			logger.Info("wrote SBOM", zap.String("path", runAllSBOMOut), zap.String("format", runAllSBOMFormat))
		}
	}

	keys, err := sbom.ReadDirectDeps(sbomBytes)
	if err != nil {
		if !runAllContinueOnError {
			return fmt.Errorf("parsing SBOM direct deps: %w", err)
		}
		logger.Warn("parsing SBOM direct deps failed; continuing with local-only report", zap.Error(err))
		fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("SBOM parse failed: %v", err))
		return writeMergedReport(outPath, localRun, nil)
	}

	auditRuns, err := auditDirectDeps(ctx, keys, overridesHash)
	if err != nil {
		if !runAllContinueOnError {
			return err
		}
		logger.Warn("audit failed; continuing with partial report", zap.Error(err))
		fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("audit failed: %v", err))
	}

	return writeMergedReport(outPath, localRun, auditRuns)
}

// scoreLocalSourceRun runs the source DAG + policy evaluation + SARIF
// conversion and returns the single sarif.Run for the local repo.
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

// auditDirectDeps runs the parallel audit pipeline (same as `audit`) and
// returns the per-package Runs. Returns an empty slice if keys is empty.
func auditDirectDeps(ctx context.Context, keys []string, overridesHash string) ([]*sarif.Run, error) {
	if len(keys) == 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("no direct dependencies to audit"))
		return nil, nil
	}

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

	runs, totals, err := scoreAll(ctx, keys, overridesHash, checkMetadata, auditJobs, cacheCfg)
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

// writeMergedReport builds a SARIF 2.1.0 report containing localRun followed
// by every audit run (in the order scoreAll returned them) and writes it to
// outPath.
func writeMergedReport(outPath string, localRun *sarif.Run, auditRuns []*sarif.Run) error {
	report, err := sarif.New(sarif.Version210, true)
	if err != nil {
		return fmt.Errorf("creating SARIF report: %w", err)
	}
	report.AddRun(localRun)
	for _, r := range auditRuns {
		report.AddRun(r)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		return fmt.Errorf("creating SARIF output directory: %w", err)
	}
	if err := report.WriteFile(outPath); err != nil {
		return fmt.Errorf("writing SARIF: %w", err)
	}

	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "\nWrote %d runs to %s\n", 1+len(auditRuns), outPath)
	return nil
}
