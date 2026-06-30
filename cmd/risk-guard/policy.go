package main

import (
	"fmt"
	"os"
	"path/filepath"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
)

var (
	addEFAll   bool
	addEFSarif string

	addEFRiskGuard       bool
	addEFRiskGuardCommit string
	addEFRiskGuardToken  string
	addEFRiskGuardServer string
)

// policyCmd is a help-only parent group for commands that read or edit the
// repository's .risk-guard.yml.
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Inspect and edit .risk-guard.yml",
	Long:  "Parent command for reading and mutating the repository's .risk-guard.yml policy file.",
}

var policyShowCmd = &cobra.Command{
	Use:   "show [path]",
	Short: "Print the effective policy (built-in default overlaid with the repo's .risk-guard.yml)",
	Long: `Print the effective policy that would be enforced for the repo at [path]
(default .): the built-in default policy overlaid with the repo's
.risk-guard.yml. This is the resolved view the evaluator uses, so it includes
every severity rule the repo inherits from the default, not just the keys
written in the file.`,
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runPolicyShow,
}

var addExpectedFailuresCmd = &cobra.Command{
	Use:   "add-expected-failures [path]",
	Short: "Merge blocking findings from a SARIF report into expected_failures in .risk-guard.yml",
	Long: `Read a SARIF report (-s, default ./risk-guard-report.sarif) and add its
blocking (error-level) findings to expected_failures in the .risk-guard.yml of
the repo at [path] (default .), merging with any existing entries (union of
check codes per entity).

With --all every finding is added; otherwise you are prompted per finding, which
requires an interactive terminal.`,
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runAddExpectedFailures,
}

var policyChecksCmd = &cobra.Command{
	Use:   "checks",
	Short: "List all available checks and their risk categories",
	Long: `List every check risk-guard can run, with its risk categories and a short
description. Categories are colored to mirror how the default policy grades them.`,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runPolicyChecks,
}

func init() {
	addExpectedFailuresCmd.Flags().BoolVar(&addEFAll, "all", false, "Add all findings without prompting")
	addExpectedFailuresCmd.Flags().StringVarP(&addEFSarif, "sarif", "s", defaultUnifiedSARIF, "SARIF report to read findings from (with --risk-guard: where to save the fetched SARIF)")
	addExpectedFailuresCmd.Flags().BoolVar(&addEFRiskGuard, "risk-guard", false, "Fetch findings from the Risk Guard server for the current repo+commit instead of a local SARIF file")
	addExpectedFailuresCmd.Flags().StringVar(&addEFRiskGuardCommit, "commit", "", "Commit SHA to look up (default: HEAD); only with --risk-guard")
	addExpectedFailuresCmd.Flags().StringVar(&addEFRiskGuardToken, "token", "", "GitHub token for the Risk Guard server (default: $RISK_GUARD_TOKEN, $GITHUB_TOKEN, or 'gh auth token'); only with --risk-guard")
	addExpectedFailuresCmd.Flags().StringVar(&addEFRiskGuardServer, "server", "", "Risk Guard server base URL (default: $RISK_GUARD_URL or https://ossriskguard.app); only with --risk-guard")

	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(addExpectedFailuresCmd)
	policyCmd.AddCommand(policyChecksCmd)
	rootCmd.AddCommand(policyCmd)
}

func runPolicyChecks(_ *cobra.Command, _ []string) error {
	checks, _ := dag_builder.GetAllCheckMetadata(localdag.Builder)
	_, err := fmt.Fprint(os.Stdout, renderCheckList(checks))
	return err
}

// repoArg returns the optional positional repo path, defaulting to "." when
// omitted — matching init/scan/sbom which all take the repo path positionally.
func repoArg(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	return "."
}

func runPolicyShow(_ *cobra.Command, args []string) error {
	repoPath, err := resolveScanPath(repoArg(args))
	if err != nil {
		return err
	}

	res, raw, err := loadRepoPolicy(repoPath)
	if err != nil {
		return err
	}
	var repoPolicy *policy.CompiledPolicy
	if res != nil {
		repoPolicy = res.Policy
	}

	// Resolve the same way the evaluator does: default base overlaid with the
	// repo's overrides, so the view includes every severity rule the repo
	// inherits from the default — not just the keys written in the file.
	effective := policy.Resolve(nil, repoPolicy, nil)
	out := renderEffectivePolicy(repoPath, policy.ToPolicy(effective), len(raw) > 0)
	_, err = fmt.Fprint(os.Stdout, out)
	return err
}

func runAddExpectedFailures(cmd *cobra.Command, args []string) error {
	// Resolve the target the same way init/run do so we read and write the exact
	// .risk-guard.yml the rest of the tool uses at the named path.
	repoPath, err := resolveScanPath(repoArg(args))
	if err != nil {
		return err
	}

	var report *sarif.Report
	if addEFRiskGuard {
		report, err = fetchRiskGuardReport(cmd.Context(), repoPath)
		if err != nil {
			return err
		}
	} else {
		if _, statErr := os.Stat(addEFSarif); statErr != nil {
			sarifUnusableHint(repoPath, addEFSarif,
				fmt.Sprintf("No SARIF report at %s", addEFSarif))
			return errReported
		}
		report, err = sarif.Open(addEFSarif)
		if err != nil {
			sarifUnusableHint(repoPath, addEFSarif,
				fmt.Sprintf("SARIF report %s could not be read: %v", addEFSarif, err))
			return errReported
		}
	}

	findings := collectInitFindings(report, levelError)
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "No blocking findings in SARIF; nothing to add.")
		return nil
	}

	// Load the existing policy as the merge target; start minimal when there is
	// no .risk-guard.yml yet.
	res, _, err := loadRepoPolicy(repoPath)
	if err != nil {
		return err
	}
	var pol *policy.Policy
	if res != nil && res.Policy != nil {
		// loadRepoPolicy returns the compiled form; ToPolicy round-trips it back
		// to the writable struct (the same conversion ToYAML uses). Overrides are
		// not part of the compiled policy, so carry them over separately —
		// otherwise the rewrite would silently drop the file's overrides section.
		pol = policy.ToPolicy(res.Policy)
		pol.Overrides = res.Overrides
	} else {
		pol = minimalPolicy()
	}

	cfgPath := filepath.Join(repoPath, initFileName)

	picked := map[string]map[string]struct{}{}
	if addEFAll {
		for _, f := range findings {
			addPick(picked, f.EntityKey, f.CheckCode)
		}
	} else {
		if !isInteractive() {
			return fmt.Errorf("non-interactive terminal: pass --all to add all %d finding(s)", len(findings))
		}
		if err := reviewEachInto(findings, picked, triageFailures); err != nil {
			return err
		}
	}

	// Nothing selected (interactive review where every finding was kept): don't
	// rewrite the file or claim an update that didn't happen.
	if len(picked) == 0 {
		fmt.Fprintf(os.Stderr, "No findings acknowledged; %s unchanged.\n", cfgPath)
		return nil
	}

	mergeExpectedFailures(pol, picked, "Acknowledged via risk-guard policy add-expected-failures")

	if err := writeConfig(cfgPath, pol); err != nil {
		return err
	}
	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "Updated %s\n", cfgPath)
	return nil
}

// sarifUnusableHint prints a colored explanation and the exact command to
// (re)generate the SARIF, for when the report is missing or invalid. The caller
// is already running add-expected-failures, so it does not echo that command
// back — only how to produce the report it needs.
func sarifUnusableHint(repoPath, sarifPath, headline string) {
	// Only spell out --sarif when it isn't the default the scan already writes to.
	gen := "risk-guard " + repoPath
	if sarifPath != defaultUnifiedSARIF {
		gen += " --sarif " + sarifPath
	}
	fmt.Fprintf(os.Stderr, "%s\n", color.YellowString("%s", headline))
	fmt.Fprintf(os.Stderr, "%s\n", color.HiBlackString("Generate it by scanning the repo, then re-run this command:"))
	fmt.Fprintf(os.Stderr, "  %s\n", color.CyanString("%s", gen))
}
