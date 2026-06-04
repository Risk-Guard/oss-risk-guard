package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/term"
	"sigs.k8s.io/yaml"
)

const initFileName = ".risk-guard.yml"

var initForce bool

var initCmd = &cobra.Command{
	Use:   "init [path]",
	Short: "Run an initial scan and write a .risk-guard.yml seeded from the findings",
	Long: `Run the full risk-guard pipeline against the repository, then prompt for
how to handle the findings and write a .risk-guard.yml at the repo root.

Refuses to overwrite an existing .risk-guard.yml unless --force is given.
In non-interactive mode (stdin or stderr is not a TTY) writes a minimal config
and leaves all findings at default severity.`,
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite an existing .risk-guard.yml")
	registerRunAllFlags(initCmd)
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) == 1 {
		path = args[0]
	}
	repoPath, err := resolveScanPath(path)
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(repoPath, initFileName)
	if !initForce {
		if _, err := os.Stat(cfgPath); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", cfgPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking for existing %s: %w", initFileName, err)
		}
	}

	report, err := runInitPipeline(cmd, repoPath, nil)
	if err != nil {
		return err
	}

	outPath := sarifOutFile
	if outPath == "" {
		outPath = defaultUnifiedSARIF
	}
	if err := writeReport(report, outPath); err != nil {
		return err
	}

	bold := color.New(color.Bold).FprintfFunc()
	pol := minimalPolicy()

	// Offer to correct unresolvable/missing source URLs first, then re-audit the
	// affected packages so the baseline below reflects the corrected source.
	if isInteractive() {
		report, err = triageSourceURLs(cmd, repoPath, report, outPath, pol)
		if err != nil {
			return err
		}
	}

	findings := collectInitFindings(report, levelError)
	warnings := collectInitFindings(report, levelWarning)

	switch {
	case len(findings) == 0 && len(warnings) == 0:
		bold(os.Stderr, "\nNo blocking or warning findings to triage.\n")
	case !isInteractive():
		fmt.Fprintf(os.Stderr, "\nnon-interactive; leaving %d finding(s) at default severity\n", len(findings)+len(warnings))
	default:
		// Blocking findings first (expected_failures), then warnings
		// (expected_warnings): each is its own render → intro → prompt pass.
		if len(findings) > 0 {
			ef, err := triageInitSection(report, findings, levelError, triageFailures)
			if err != nil {
				return err
			}
			pol.ExpectedFailures = ef
		}
		if len(warnings) > 0 {
			ew, err := triageInitSection(report, warnings, levelWarning, triageWarnings)
			if err != nil {
				return err
			}
			pol.ExpectedWarnings = ew
		}
	}

	if err := writeConfig(cfgPath, pol); err != nil {
		return err
	}
	bold(os.Stderr, "Wrote %s\n", cfgPath)
	return nil
}

// runInitPipeline mirrors runAll but keeps the SARIF report in memory and
// degrades to a local-only report when SBOM or audit fails, so init can always
// reach the triage step.
func runInitPipeline(cmd *cobra.Command, repoPath string, overrides map[string][]policy.PolicyOverride) (*sarif.Report, error) {
	if auditJobs < 1 {
		return nil, fmt.Errorf("--jobs must be >= 1")
	}

	ctx, overridesHash, err := setupAuditContext(cmd, repoPath)
	if err != nil {
		return nil, err
	}
	// Inject interactively-collected source-URL overrides so the per-package
	// audit applies them (and only the affected packages re-score — their cache
	// key changes; the rest are served from cache).
	if len(overrides) > 0 {
		ctx = policy.SetRootPolicy(ctx, policy.DefaultPolicy(), "", overrides)
	}
	logger := ctxutil.GetLogger(ctx)

	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "Scoring local source: %s\n", repoPath)
	localViolations, sourceInput, err := scoreLocalSource(ctx, repoPath, overridesHash)
	if err != nil {
		return nil, fmt.Errorf("scoring local source: %w", err)
	}

	var (
		depViolations []*violations.AnalysisViolations
		failures      []packageError
		locByKey      map[string]*models.LocationInfo
	)
	bold(os.Stderr, "Building SBOM (%s)…\n", runAllSBOMFormat)
	sbomBytes, sbomErr := buildSBOMBytes(ctx, repoPath, runAllSBOMFormat)
	if sbomErr != nil {
		logger.Warn("building SBOM failed; continuing local-only", zap.Error(sbomErr))
		fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("building SBOM failed: %v", sbomErr))
	} else {
		deps, derr := sbom.ReadDirectDepsWithLocations(sbomBytes)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("parsing SBOM failed: %v", derr))
		} else {
			var keys []string
			keys, locByKey = keysAndLocations(deps)
			audited, fails, aerr := runPackageAudits(ctx, keys, locByKey, overridesHash)
			if aerr != nil {
				logger.Warn("audit failed; continuing with partial report", zap.Error(aerr))
				fmt.Fprintf(os.Stderr, "  %s\n", color.YellowString("audit failed: %v", aerr))
			}
			depViolations = audited
			failures = fails
		}
	}

	return assembleReport(ctx, sourceInput.AnalysisIdentifier, localViolations, depViolations, failures, locByKey)
}

// triageInitSection renders the findings at one level, explains the baseline
// rationale, prompts, and returns the entries to record in the target section.
func triageInitSection(report *sarif.Report, findings []finding, level string, t triageTarget) (map[string]policy.ExpectedFailureV2, error) {
	fmt.Fprintln(os.Stderr)
	if err := renderFindings(selectFindingsByLevel(report, levelEquals(level)), []Printer{newTextPrinter(os.Stderr)}); err != nil {
		return nil, fmt.Errorf("rendering %s findings: %w", level, err)
	}
	fmt.Fprintln(os.Stderr)
	printTriageIntro(t, len(findings))
	return triageInitFindings(findings, t)
}

// printTriageIntro explains, before the prompt, why init offers to acknowledge
// findings as a baseline. The rationale differs by section: blocking findings
// would otherwise fail every build; warnings are non-blocking but pile up as
// annotation noise on a repo with a long code history. Either way, baselining
// today's findings lets the team adopt Risk Guard now and still enforce the
// full policy on each new pull request.
func printTriageIntro(t triageTarget, n int) {
	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "Found %d existing %s from your current code history.\n", n, pluralize(t.noun, n))
	if t.section == triageWarnings.section {
		fmt.Fprintln(os.Stderr, "Warnings don't fail the build, but on an established repo they pile up as")
		fmt.Fprintln(os.Stderr, "annotation noise on code you haven't touched.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Ignoring them records today's warnings as a baseline (expected_warnings) so the")
		fmt.Fprintln(os.Stderr, "noise clears now — while new pull requests still surface fresh warnings. Work")
		fmt.Fprintln(os.Stderr, "the baseline off over time as you fix the underlying issues.")
	} else {
		fmt.Fprintln(os.Stderr, "Adopting Risk Guard as-is, these would block every build until each is fixed.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Ignoring them records today's findings as an accepted baseline (expected_failures)")
		fmt.Fprintln(os.Stderr, "so you can move forward now — while every new pull request is still held to the")
		fmt.Fprintln(os.Stderr, "full policy. Work the baseline off over time as you fix the underlying issues.")
	}
	fmt.Fprintln(os.Stderr)
}

func minimalPolicy() *policy.Policy {
	return &policy.Policy{
		Version:  policy.CurrentVersion,
		Workflow: &policy.WorkflowConfig{Mode: policy.WorkflowModeActive},
	}
}

func writeConfig(path string, pol *policy.Policy) error {
	data, err := yaml.Marshal(pol)
	if err != nil {
		return fmt.Errorf("marshaling policy: %w", err)
	}
	const header = "# Risk Guard configuration\n# See docs/configuration.md for the full schema.\n\n"
	if err := os.WriteFile(path, append([]byte(header), data...), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func isInteractive() bool {
	//nolint:gosec // Fd() values for stdin/stderr are 0 and 2; no overflow risk.
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// resolveScanPath resolves the user-supplied path to the absolute directory the
// command operates on: the scan target and the location of .risk-guard.yml. It
// is intentionally NOT git-aware — the path you name is the path used, whether
// or not it is a git repo or a subdirectory of one. Discovering the enclosing
// git work tree (for history checks) is a separate concern handled inside the
// scoring DAG, and never changes what gets scanned or where the config lives.
func resolveScanPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path does not exist: %s", abs)
		}
		return "", fmt.Errorf("accessing path: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path is not a directory: %s", abs)
	}
	return abs, nil
}
