package main

import (
	"fmt"
	"os"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
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
	repoPath, err := git.ValidateGitRepo(args[0])
	if err != nil {
		return fmt.Errorf("invalid git repository: %w", err)
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

	depViolations, failures, err := runPackageAudits(ctx, keys, overridesHash)
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

	printPolicySummary(report)

	if err := renderReport(os.Stdout, os.Stderr, report, runAllDisplayMode(effectiveMode), "all", nil, repoPath); err != nil {
		return err
	}

	// GitLab output is independent of --github: --github writes annotations to
	// stdout, --gitlab writes a Code Quality report file; both may be set. Gate
	// on emitsAnnotations to match --github semantics (silent/disabled suppress).
	if runAllGitLab != "" && emitsAnnotations(effectiveMode) {
		if err := writeGitLabReport(runAllGitLab, report, "all", nil, repoPath); err != nil {
			return err
		}
	}

	if failsOnBlocking(effectiveMode) && reportHasErrorLevel(report) {
		return errBlockingFindings
	}
	return nil
}

// writeGitLabReport renders a GitLab Code Quality (CodeClimate) report for the
// in-memory SARIF and writes it to path (created/truncated). Diagnostics about
// skipped findings go to stderr.
func writeGitLabReport(path string, report *sarif.Report, level string, packages []string, repoRoot string) error {
	f, err := os.Create(path) //nolint:gosec // path is an operator-supplied --gitlab output file
	if err != nil {
		return fmt.Errorf("creating GitLab report %s: %w", path, err)
	}
	defer func() { _ = f.Close() }() // backstop for the error return below
	if err := renderGitLab(f, os.Stderr, report, level, packages, repoRoot); err != nil {
		return fmt.Errorf("writing GitLab report %s: %w", path, err)
	}
	// Close explicitly so a deferred-write error (e.g. ENOSPC surfaced only at
	// close on some filesystems) is reported rather than silently dropped.
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing GitLab report %s: %w", path, err)
	}
	return nil
}

// runAllDisplayMode maps --github + effective workflow mode to a DisplayMode.
// silent and disabled suppress annotations even when --github is set; the user
// asked for the scan to run and SARIF to be written but explicitly opted out
// of GH annotations.
func runAllDisplayMode(mode policy.WorkflowMode) DisplayMode {
	if runAllGitHub && emitsAnnotations(mode) {
		return DisplayGitHub
	}
	return DisplayNone
}
