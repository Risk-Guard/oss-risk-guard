package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
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
	repoPath, err := git.ValidateGitRepo(path)
	if err != nil {
		return fmt.Errorf("invalid git repository: %w", err)
	}

	cfgPath := filepath.Join(repoPath, initFileName)
	if !initForce {
		if _, err := os.Stat(cfgPath); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", cfgPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking for existing %s: %w", initFileName, err)
		}
	}

	report, err := runInitPipeline(cmd, repoPath)
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

	findings := collectInitFindings(report)
	bold := color.New(color.Bold).FprintfFunc()

	pol := minimalPolicy()
	if len(findings) == 0 {
		bold(os.Stderr, "\nNo blocking or warning findings to triage.\n")
	} else if !isInteractive() {
		fmt.Fprintf(os.Stderr, "\nnon-interactive; leaving %d finding(s) at default severity\n", len(findings))
	} else {
		fmt.Fprintln(os.Stderr)
		if err := renderReport(os.Stderr, os.Stderr, report, DisplayText, "all", nil, ""); err != nil {
			return fmt.Errorf("rendering findings: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		decision, err := chooseTriageMode(len(findings))
		if err != nil {
			return err
		}
		switch decision {
		case triageIgnoreAll:
			pol.ExpectedFailures = buildExpectedFailures(findings)
		case triageReviewEach:
			if err := reviewEach(findings, pol); err != nil {
				return err
			}
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
func runInitPipeline(cmd *cobra.Command, repoPath string) (*sarif.Report, error) {
	if auditJobs < 1 {
		return nil, fmt.Errorf("--jobs must be >= 1")
	}

	ctx, overridesHash, err := setupAuditContext(cmd, repoPath)
	if err != nil {
		return nil, err
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
			audited, fails, aerr := runPackageAudits(ctx, keys, overridesHash)
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
