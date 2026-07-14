package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"
	"github.com/Risk-Guard/oss-risk-guard/src/ui"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

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

	runAllRiskGuard bool
	runAllRGCommit  string
	runAllRGToken   string
	runAllRGServer  string
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
	levelFilter, err := levelFilterFor(findingLevel)
	if err != nil {
		return err
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

	bold := color.New(color.Bold).SprintfFunc()
	disp := ui.FromContext(ctx)
	disp.Printf("%s", bold("Scoring local source: %s\n", repoPath))

	// A ticking row so the early work (git resolve, package detection, checks)
	// isn't silent. The DAG executor reports each node it runs under this span,
	// so the row names the current activity, and the registry prefetch adds its
	// own per-package rows underneath while this one runs.
	localViolations, sourceInput, err := withPhase2(ctx, "scoring local source", 0, func(sctx context.Context) (*violations.AnalysisViolations, dag_impl.Input, error) {
		return scoreLocalSource(sctx, repoPath, overridesHash)
	})
	if err != nil {
		return fmt.Errorf("scoring local source: %w", err)
	}

	// The SBOM phase prints its manifest inventory as it goes. That is safe to
	// do underneath a live row now only because every one of those lines goes
	// through the UI, which erases the rows before printing and repaints after.
	sbomBytes, err := withPhase(ctx, "building SBOM", func(bctx context.Context) ([]byte, error) {
		return buildSBOMBytes(bctx, repoPath, runAllSBOMFormat)
	})
	if err != nil {
		return softFailLocalOnly(ctx, outPath, sourceInput.AnalysisIdentifier, localViolations, "building SBOM", err, logger)
	}
	if runAllSBOMOut != "" {
		if err := persistSBOM(runAllSBOMOut, sbomBytes, logger); err != nil {
			return err
		}
	}

	// Offload: source checks were run locally above; hand the SBOM + source findings to the server,
	// which scores the dependencies and records the run (no local dep audit or SARIF).
	if runAllRiskGuard {
		return uploadSBOMToRiskGuard(ctx, repoPath, sbomBytes, violationsToChecks(localViolations), runAllRGCommit, runAllRGToken, runAllRGServer)
	}

	deps, err := sbom.ReadDirectDepsWithLocations(sbomBytes)
	if err != nil {
		return softFailLocalOnly(ctx, outPath, sourceInput.AnalysisIdentifier, localViolations, "parsing SBOM direct deps", err, logger)
	}
	keys, locByKey := keysAndLocations(deps)

	srcFindings := sourceFindingCount(localViolations)
	depViolations, failures, err := runPackageAudits(ctx, keys, locByKey, overridesHash, &srcFindings)
	if err != nil {
		if !runAllContinueOnError {
			return err
		}
		logger.Warn("audit failed; continuing with partial report", zap.Error(err))
		disp.Printf("  %s\n", color.YellowString("audit failed: %v", err))
	}

	report, err := assembleReport(ctx, sourceInput.AnalysisIdentifier, localViolations, depViolations, failures, locByKey)
	if err != nil {
		return err
	}
	if err := writeReport(report, outPath); err != nil {
		return err
	}

	return renderReport(report, effectiveMode, runAllGitHub, runAllGitLab, repoPath, outPath, levelFilter, nil)
}

// renderReport is the one output pipeline `run`/`checks` and `audit view` share.
// Given a finished report it prints the policy summary, the live findings (to
// text or --github/--gitlab sinks), and the pass/fail verdict — identical
// whether the report came from a fresh scan or was read off disk, because the
// only thing that differs between the two commands is where the report came
// from. mode gates output and decides whether blocking findings fail the run;
// repoRoot and sarifPath phrase the acknowledge hint and relativize file paths.
func renderReport(report *sarif.Report, mode policy.WorkflowMode, toGitHub bool, gitlabPath, repoRoot, sarifPath string, levelFilter func(string) bool, pkgFilter func(string) bool) error {
	printPolicySummary(report, pkgFilter)
	findings := selectFindingsByLevel(report, levelFilter)
	// pkgFilter narrows the displayed findings to a subject the caller named
	// (the --package flag on `audit view`); nil keeps every package. Like the
	// level filter, it only shapes what is rendered — the policy summary and
	// verdict above/below still reflect the whole report, so filtering the view
	// never changes the pass/fail outcome.
	if pkgFilter != nil {
		findings = keepMatchingPackages(findings, pkgFilter)
	}
	if err := renderFindings(findings, reportPrinters(mode, toGitHub, gitlabPath, repoRoot)); err != nil {
		return err
	}
	return printRunVerdict(mode, report, repoRoot, sarifPath)
}

// renderReportSummary prints an in-memory report the same way `run` and
// `audit view` do: policy summary, live findings, and a pass/fail verdict (with
// the matching exit code). The audit subcommands call this when no output-file
// flag is set, so a bare `audit source/deps/package` prints a useful summary
// instead of running the DAG and exiting silently. modeOverride/toGitHub/
// gitlabPath shape the output exactly as on `run`/`audit view` — this is the
// whole point of the shared renderReport pipeline. The workflow mode is resolved
// from repoRoot's .risk-guard.yml (with modeOverride winning); no SARIF path is
// passed because nothing was written to disk.
func renderReportSummary(report *sarif.Report, modeOverride string, toGitHub bool, gitlabPath, repoRoot string) error {
	mode, err := resolveWorkflowMode(modeOverride, repoRoot)
	if err != nil {
		return err
	}
	levelFilter, err := levelFilterFor(findingLevel)
	if err != nil {
		return err
	}
	return renderReport(report, mode, toGitHub, gitlabPath, repoRoot, "", levelFilter, nil)
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
	// outPath is empty when the summary was rendered from an in-memory report
	// (no --sarif); only point -s at a real, non-default file.
	if outPath != "" && outPath != defaultUnifiedSARIF {
		ack += " -s " + outPath
	}
	ack += " --all"
	fmt.Fprintf(os.Stderr, "%s\n  %s\n  %s\n",
		color.HiBlackString("To acknowledge these findings in %s, run:", policy.PolicyFileName),
		color.CyanString("%s", ack),
		color.HiBlackString("(drop --all to review each finding interactively)"))
	return errBlockingFindings
}
