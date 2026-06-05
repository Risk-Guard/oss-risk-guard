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
	"github.com/Risk-Guard/oss-risk-guard/src/policy"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

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
// repeat. When repoPath is non-empty its .risk-guard.yml is also loaded and
// stashed in context via policy.SetRootPolicy, so every DAG in the run
// (local-source and per-package audits) sees the same user-supplied policy.
// Returns the augmented ctx (also written back to cmd via cmd.SetContext)
// and the overrides hash for use by package Inputs.
func setupAuditContext(cmd *cobra.Command, repoPath string) (context.Context, string, error) {
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
	if repoPath != "" {
		res, raw, err := loadRepoPolicy(repoPath)
		if err != nil {
			return nil, "", err
		}
		if res != nil && res.Policy != nil {
			ctx = policy.SetRootPolicy(ctx, res.Policy, string(raw), res.Overrides)
		}
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

// runPackageAudits owns the per-batch audit progress UI and scoring loop.
// Returns the raw per-package violations and any per-package failures. The
// rulebook is NOT applied here — that happens once at merge time.
func runPackageAudits(ctx context.Context, keys []string, locByKey map[string]*models.LocationInfo, overridesHash string, sourceFindings *int) ([]*violations.AnalysisViolations, []packageError, error) {
	if len(keys) == 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("no direct dependencies to audit"))
		printSourceFindings(sourceFindings)
		return nil, nil, nil
	}

	logger := ctxutil.GetLogger(ctx)
	checkMetadata, _ := dag_builder.GetAllCheckMetadata(localdag.PackageBuilder)
	cacheCfg, err := buildCacheConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("building audit cache config: %w", err)
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

	analyses, failures, totals, err := scoreAll(ctx, keys, locByKey, overridesHash, checkMetadata, auditJobs, cacheCfg)
	if err != nil {
		return nil, nil, err
	}

	fmt.Fprintf(os.Stderr, "  %s  %s\n",
		color.YellowString("%d findings across %d unique dependency packages", totals.findings, totals.scored),
		color.HiBlackString("(severity applied at merge)"))
	printSourceFindings(sourceFindings)
	if totals.failed > 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", color.RedString("%d packages failed to score", totals.failed))
	}
	if cacheCfg.enabled {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("%d/%d packages served from cache", totals.cached, len(keys)))
	}
	return analyses, failures, nil
}

// printSourceFindings prints the local-source pre-grade finding count beneath
// the dependency tally so the two reconcile against the post-grade "Policy
// result" total. A nil count means the command scans no local source (e.g.
// `audit`), so the line is omitted rather than printed as "0 findings in source".
func printSourceFindings(n *int) {
	if n == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("%d findings in source", *n))
}

// sourceFindingCount counts the pre-grade violations from the local-source scan
// the same way per-package findings are counted (len of the violations slice),
// so "N findings in source" lines up with "M findings across … packages".
func sourceFindingCount(v *violations.AnalysisViolations) int {
	if v == nil {
		return 0
	}
	return len(v.Violations)
}

// assembleReport runs the merge step: applies the resolved root policy
// against the union of local + per-package violations, converts to SARIF,
// stamps physical locations from the SBOM, and appends synthetic Runs for
// any per-package failures so they still drive exit code.
func assembleReport(ctx context.Context, sourceID string, local *violations.AnalysisViolations, deps []*violations.AnalysisViolations, failures []packageError, locByKey map[string]*models.LocationInfo) (*sarif.Report, error) {
	po := policyOverride
	if po == "" {
		po = policyFile
	}
	result, err := gradeViolations(ctx, sourceID, local, deps, po, policyDefault)
	if err != nil {
		return nil, err
	}

	checkMetadata, _ := dag_builder.GetAllCheckMetadata(localdag.Builder)
	report, err := commonsarif.FromEvaluationResult(result, checkMetadata)
	if err != nil {
		return nil, fmt.Errorf("sarif conversion: %w", err)
	}
	if len(report.Runs) == 0 {
		return nil, fmt.Errorf("sarif conversion produced no runs")
	}
	gradedRun := report.Runs[0]
	if gradedRun.AutomationDetails == nil {
		gradedRun.WithAutomationDetails(sarif.NewRunAutomationDetails().WithID("risk-guard"))
	}
	applyPhysicalLocations(gradedRun, locByKey)

	for _, f := range failures {
		report.AddRun(failureRun(f))
	}

	// GitHub Code Scanning rejects any result without a physicalLocation. Source
	// findings, aggregate package checks, and failure runs have only a logical
	// location at this point; anchor whatever is left at the repository root.
	commonsarif.EnsurePhysicalLocations(report)
	return report, nil
}

// applyPhysicalLocations stamps every result whose package matches a key in
// locByKey with the manifest-file/line where the dep was declared. Results
// for the local source (logical location kind "package" but name empty or
// missing) are left untouched.
func applyPhysicalLocations(run *sarif.Run, locByKey map[string]*models.LocationInfo) {
	if run == nil || len(locByKey) == 0 {
		return
	}
	for _, res := range run.Results {
		key := packageKeyFromResult(res)
		if key == "" {
			continue
		}
		loc, ok := locByKey[key]
		if !ok || loc == nil || loc.File == nil {
			continue
		}
		if len(res.Locations) == 0 {
			res.Locations = []*sarif.Location{sarif.NewLocation()}
		}
		phys := sarif.NewPhysicalLocation().
			WithArtifactLocation(sarif.NewSimpleArtifactLocation(*loc.File))
		if loc.LineNumber != nil {
			phys = phys.WithRegion(sarif.NewSimpleRegion(*loc.LineNumber, *loc.LineNumber))
		}
		res.Locations[0].WithPhysicalLocation(phys)
	}
}

func packageKeyFromResult(res *sarif.Result) string {
	for _, loc := range res.Locations {
		if loc == nil {
			continue
		}
		for _, ll := range loc.LogicalLocations {
			if ll == nil || ll.Name == nil {
				continue
			}
			return *ll.Name
		}
	}
	return ""
}

// auditErrorRuleID is the synthetic rule ID used for audit-time scoring
// failures (see failureRun). It is an operational error, not a policy check,
// so init triage skips it (see collectInitFindings).
const auditErrorRuleID = "AUDIT_ERROR"

// failureRun synthesizes a SARIF Run for a single audit-time failure so the
// user sees the package in the merged report. Always level=error so the run
// drives exit code under workflow.mode=active.
func failureRun(f packageError) *sarif.Run {
	run := sarif.NewRunWithInformationURI("risk-guard", commonsarif.InformationURI)
	run.AddRule(auditErrorRuleID).
		WithShortDescription(sarif.NewMultiformatMessageString("Failed to score package during audit"))

	res := run.CreateResultForRule(auditErrorRuleID).
		WithLevel("error").
		WithMessage(sarif.NewTextMessage(fmt.Sprintf("failed to score %s: %v", f.Name, f.Err)))

	// Match graded results, whose logical location name is the package key
	// (see commonsarif convert: Finding.Package == analysis identifier), so
	// downstream key matching (physical-location stamping, init triage) lines
	// up. The human-friendly name lives in the message above.
	key := f.Key
	kind := "package"
	res.WithLocations([]*sarif.Location{
		sarif.NewLocation().WithLogicalLocations([]*sarif.LogicalLocation{{
			Name: &key,
			Kind: &kind,
		}}),
	})
	return run
}

// softFailLocalOnly handles the runAll continue-on-error branches that occur
// after the local-source scan succeeded but before audit could proceed. When
// runAllContinueOnError is false, returns a wrapped fatal error; otherwise
// logs the failure, prints a yellow stderr line, and emits a local-only
// graded report.
func softFailLocalOnly(ctx context.Context, outPath, sourceID string, local *violations.AnalysisViolations, step string, cause error, logger *zap.Logger) error {
	if !runAllContinueOnError {
		return fmt.Errorf("%s: %w", step, cause)
	}
	logger.Warn(step+" failed; continuing with local-only report", zap.Error(cause))
	fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("%s failed: %v", step, cause))
	report, err := assembleReport(ctx, sourceID, local, nil, nil, nil)
	if err != nil {
		return err
	}
	return writeReport(report, outPath)
}

// printPolicySummary prints a post-grading tally to stderr: how many SARIF
// results landed at each level after the rulebook was applied. This is the
// "policy violations" view, distinct from the pre-grade "findings" total
// printed by runPackageAudits.
func printPolicySummary(report *sarif.Report) {
	var blocking, warning, ack, ignored int
	for _, run := range report.Runs {
		for _, res := range run.Results {
			lvl := ""
			if res.Level != nil {
				lvl = *res.Level
			}
			switch lvl {
			case "error":
				blocking++
			case "warning", "":
				warning++
			case "note":
				ack++
			case "none":
				ignored++
			}
		}
	}
	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "\nPolicy result:\n")
	fmt.Fprintf(os.Stderr, "  %s  %s  %s  %s\n",
		color.RedString("%d blocking", blocking),
		color.YellowString("%d warning", warning),
		color.CyanString("%d acknowledged", ack),
		color.HiBlackString("%d ignored", ignored))
}

// writeReport persists report to outPath (mkdir-p of parent dir) and prints
// the "Wrote N runs to <path>" line to stderr. outPath must be non-empty.
func writeReport(report *sarif.Report, outPath string) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		return fmt.Errorf("creating SARIF output directory: %w", err)
	}
	// go-sarif's report.WriteFile opens with O_CREATE|O_WRONLY but no O_TRUNC,
	// so rewriting a shorter report over a longer existing file leaves stale
	// trailing bytes and produces invalid JSON. os.Create truncates first.
	f, err := os.Create(outPath) //nolint:gosec // outPath is an operator-supplied --sarif output file
	if err != nil {
		return fmt.Errorf("creating SARIF file: %w", err)
	}
	if err := report.PrettyWrite(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing SARIF: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing SARIF file: %w", err)
	}
	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "\nWrote %d runs to %s\n", len(report.Runs), outPath)
	return nil
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

// scoreLocalSource runs the source DAG and extracts the raw violations for
// the user's repository. Grading happens later at merge time, alongside
// every per-package audit.
func scoreLocalSource(ctx context.Context, repoPath, overridesHash string) (*violations.AnalysisViolations, dag_impl.Input, error) {
	input := dag_impl.NewSourceInputWithOverrides(repoPath, nil, false, overridesHash)
	dagResponse, err := dagcmd.BuildAndRunDAG(ctx, input, localdag.Builder)
	if err != nil {
		return nil, input, fmt.Errorf("DAG execution: %w", err)
	}
	return extractAnalysisViolations(input, dagResponse.Checks), input, nil
}
