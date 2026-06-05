package main

import "github.com/spf13/cobra"

// Shared flag help strings. Centralized so a flag that means the same thing on
// the root pipeline and the `audit` subcommands reads identically everywhere —
// the per-command wording differences these replaced were drift, not intent.
const (
	flagHelpSARIF          = "Output file for the SARIF 2.1.0 report"
	flagHelpPolicyOverride = "Policy file that completely overrides all policy (YAML)"
	flagHelpPolicyDefault  = "Policy file to use as base instead of global default (YAML)"
	flagHelpJobs           = "Maximum number of packages to audit in parallel"
	flagHelpMaxAge         = "Maximum audit cache age (e.g. 30m, 48h, 2d). 0 disables caching"
	flagHelpNoCache        = "Force fresh audit scoring; do not read or write the audit cache"

	flagHelpMode     = "Override workflow.mode from .risk-guard.yml: active (fail on blocking), no-fail/silent (never fail), disabled (refuse to run)"
	flagHelpGitHub   = "Emit GitHub Actions workflow annotations on stdout instead of the text summary"
	flagHelpGitLab   = "Write a GitLab Code Quality (CodeClimate) report to this file (e.g. gl-code-quality-report.json)"
	flagHelpRepoRoot = "Repo root: where .risk-guard.yml lives and what file paths are relative to (defaults to $GITHUB_WORKSPACE/$CI_PROJECT_DIR then CWD)"
	flagHelpLevel    = "Lowest finding level to display: blocking, warning, acknowledged, or all (shows that level and every more-severe one)"
)

// Shared globals for the summary-render flags. The `audit source/deps/package`
// commands print a report via renderReportSummary; these flags shape that output
// the same way --mode/--github/--gitlab/--repo-root shape `run` and `audit view`.
// Only one command runs per invocation, so a single shared set is safe (same
// pattern as sarifOutFile, policyOverride, etc.).
var (
	summaryModeOverride string
	summaryGitHub       bool
	summaryGitLab       string
	summaryRepoRoot     string
	findingLevel        string
)

// registerSummaryRenderFlags wires the flags that shape the printed summary
// (when no output-file flag is set) onto a summary-rendering audit subcommand,
// so they all expose the same render surface. repo-root is omitted for commands
// that already take a repository <path> argument (audit source), where it would
// be redundant.
func registerSummaryRenderFlags(cmd *cobra.Command, includeRepoRoot bool) {
	cmd.Flags().StringVar(&summaryModeOverride, "mode", "", flagHelpMode)
	cmd.Flags().BoolVar(&summaryGitHub, "github", false, flagHelpGitHub)
	cmd.Flags().StringVar(&summaryGitLab, "gitlab", "", flagHelpGitLab)
	if includeRepoRoot {
		cmd.Flags().StringVar(&summaryRepoRoot, "repo-root", "", flagHelpRepoRoot)
	}
	registerLevelFlag(cmd)
}

// registerLevelFlag wires --level onto any command that displays findings, so
// the display threshold reads and defaults identically everywhere.
func registerLevelFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&findingLevel, "level", levelWarning, flagHelpLevel)
}
