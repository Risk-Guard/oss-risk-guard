package main

import (
	"fmt"
	"os"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const defaultUnifiedSARIF = "./risk-guard-report.sarif"

var (
	runAllSBOMFormat      string
	runAllSBOMOut         string
	runAllContinueOnError bool
	runAllGitHub          bool
)

// runAll is the unified pipeline: score the local source repo, build an SBOM
// in memory, audit its direct dependencies, and emit one merged SARIF report
// containing the local-source Run plus one Run per audited package. With
// --github, after the SARIF is written the same in-memory report is rendered
// to stdout as GitHub Actions workflow annotations.
func runAll(cmd *cobra.Command, args []string) error {
	repoPath, err := git.ValidateGitRepo(args[0])
	if err != nil {
		return fmt.Errorf("invalid git repository: %w", err)
	}
	if auditJobs < 1 {
		return fmt.Errorf("--jobs must be >= 1")
	}

	ctx, overridesHash, err := setupAuditContext(cmd)
	if err != nil {
		return err
	}
	logger := ctxutil.GetLogger(ctx)

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
		return softFailLocalOnly(outPath, localRun, "building SBOM", err, logger)
	}
	if runAllSBOMOut != "" {
		if err := persistSBOM(runAllSBOMOut, sbomBytes, logger); err != nil {
			return err
		}
	}

	deps, err := sbom.ReadDirectDepsWithLocations(sbomBytes)
	if err != nil {
		return softFailLocalOnly(outPath, localRun, "parsing SBOM direct deps", err, logger)
	}
	keys, locByKey := keysAndLocations(deps)

	auditRuns, err := runPackageAudits(ctx, keys, locByKey, overridesHash)
	if err != nil {
		if !runAllContinueOnError {
			return err
		}
		logger.Warn("audit failed; continuing with partial report", zap.Error(err))
		fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("audit failed: %v", err))
	}

	report, err := assembleReport(localRun, auditRuns)
	if err != nil {
		return err
	}
	if err := writeReport(report, outPath); err != nil {
		return err
	}

	return renderReport(os.Stdout, os.Stderr, report, runAllDisplayMode(), "all", nil, "")
}

// runAllDisplayMode maps the --github flag to a DisplayMode. Default is
// DisplayNone: runAll's CI-friendly behavior is "write SARIF only".
func runAllDisplayMode() DisplayMode {
	if runAllGitHub {
		return DisplayGitHub
	}
	return DisplayNone
}
