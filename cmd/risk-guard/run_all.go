package main

import (
	"fmt"
	"os"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"

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
	runAllGitHub          bool
	runAllGitLab          string
	runAllModeOverride    string
)

// runAll is the unified pipeline: score the local source repo, build an SBOM
// in memory, audit its direct dependencies, and emit one merged SARIF report
// containing the local-source Run plus one Run per audited package. With
// --github, after the SARIF is written the same in-memory report is rendered
// to stdout as GitHub Actions workflow annotations.
func runAll(cmd *cobra.Command, args []string) error {
	repoPath, err := resolveScanPath(args[0])
	if err != nil {
		return err
	}
	if auditJobs < 1 {
		return fmt.Errorf("--jobs must be >= 1")
	}

	ctx, overridesHash, err := setupAuditContext(cmd, repoPath)
	if err != nil {
		return err
	}
	logger := ctxutil.GetLogger(ctx)

	// Resolve workflow.mode upfront so we (a) fail fast on invalid config
	// instead of after a full scan, and (b) can plumb a CLI override into the
	// in-DAG policy_loader via context — the documented precedence is
	// CLI > .risk-guard.yml > default, but the loader would otherwise read the
	// file unconditionally and decide on its own.
	effectiveMode, err := resolveWorkflowMode(runAllModeOverride, repoPath)
	if err != nil {
		return fmt.Errorf("resolving workflow mode: %w", err)
	}
	if runAllModeOverride != "" {
		ctx = policy.SetWorkflowModeOverride(ctx, effectiveMode)
		cmd.SetContext(ctx)
	}

	outPath := sarifOutFile
	if outPath == "" {
		outPath = defaultUnifiedSARIF
	}

	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "Scoring local source: %s\n", repoPath)
	localViolations, sourceInput, err := scoreLocalSource(ctx, repoPath, overridesHash)
	if err != nil {
		return fmt.Errorf("scoring local source: %w", err)
	}

	bold(os.Stderr, "Building SBOM (%s)…\n", runAllSBOMFormat)
	sbomBytes, err := buildSBOMBytes(ctx, repoPath, runAllSBOMFormat)
	if err != nil {
		return softFailLocalOnly(ctx, outPath, sourceInput.AnalysisIdentifier, localViolations, "building SBOM", err, logger)
	}
	if runAllSBOMOut != "" {
		if err := persistSBOM(runAllSBOMOut, sbomBytes, logger); err != nil {
			return err
		}
	}

	deps, err := sbom.ReadDirectDepsWithLocations(sbomBytes)
	if err != nil {
		return softFailLocalOnly(ctx, outPath, sourceInput.AnalysisIdentifier, localViolations, "parsing SBOM direct deps", err, logger)
	}
	keys, locByKey := keysAndLocations(deps)

	depViolations, failures, err := runPackageAudits(ctx, keys, locByKey, overridesHash)
	if err != nil {
		if !runAllContinueOnError {
			return err
		}
		logger.Warn("audit failed; continuing with partial report", zap.Error(err))
		fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("audit failed: %v", err))
	}

	report, err := assembleReport(ctx, sourceInput.AnalysisIdentifier, localViolations, depViolations, failures, locByKey)
	if err != nil {
		return err
	}
	if err := writeReport(report, outPath); err != nil {
		return err
	}

	return renderReport(report, effectiveMode, runAllGitHub, runAllGitLab, repoPath, outPath)
}

// renderReport is the one output pipeline `run`/`checks` and `view-audit` share.
// Given a finished report it prints the policy summary, the live findings (to
// text or --github/--gitlab sinks), and the pass/fail verdict — identical
// whether the report came from a fresh scan or was read off disk, because the
// only thing that differs between the two commands is where the report came
// from. mode gates output and decides whether blocking findings fail the run;
// repoRoot and sarifPath phrase the acknowledge hint and relativize file paths.
func renderReport(report *sarif.Report, mode policy.WorkflowMode, toGitHub bool, gitlabPath, repoRoot, sarifPath string) error {
	printPolicySummary(report)
	if err := renderFindings(selectFindingsByLevel(report, isLiveLevel), reportPrinters(mode, toGitHub, gitlabPath, repoRoot)); err != nil {
		return err
	}
	return printRunVerdict(mode, report, repoRoot, sarifPath)
}

// printRunVerdict ends the run with an explicit verdict so the outcome (and
// why) is never left implicit after the "Policy result:" tally. It returns
// errBlockingFindings when the run should exit non-zero.
func printRunVerdict(mode policy.WorkflowMode, report *sarif.Report, repoPath, outPath string) error {
	blocking := countErrorLevel(report)
	switch {
	case blocking == 0:
		fmt.Fprintf(os.Stderr, "%s\n", color.GreenString("Passing (exit 0): no blocking findings"))
		return nil
	case !failsOnBlocking(mode):
		// Non-failing modes (no-fail/silent/disabled): explain the exit 0 so the
		// user isn't surprised that blocking findings did not fail the run.
		fmt.Fprintf(os.Stderr, "%s\n", color.YellowString(
			"Not failing (exit 0) because mode is %s, though policy blocks %d finding(s)",
			mode, blocking))
		return nil
	}

	fmt.Fprintf(os.Stderr, "%s\n", color.RedString(
		"Exit with status 1 because mode is %s and policy blocks %d finding(s).", mode, blocking))

	// The blocking findings themselves were already printed above by the run's
	// text/GitHub printer; the verdict just states the outcome and how to
	// acknowledge. Only spell out -s when the report isn't at the default path.
	ack := "risk-guard policy add-expected-failures " + repoPath
	if outPath != defaultUnifiedSARIF {
		ack += " -s " + outPath
	}
	ack += " --all"
	fmt.Fprintf(os.Stderr, "%s\n  %s\n  %s\n",
		color.HiBlackString("To acknowledge these findings in %s, run:", policy.PolicyFileName),
		color.CyanString("%s", ack),
		color.HiBlackString("(drop --all to review each finding interactively)"))
	return errBlockingFindings
}
