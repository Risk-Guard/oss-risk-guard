package main

import (
	"fmt"
	"os"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"

	"github.com/spf13/cobra"
)

var (
	auditSBOMFile string
	auditList     bool
	auditJobs     int
	auditMaxAge   string
	auditNoCache  bool

	auditRiskGuard bool
	auditRGCommit  string
	auditRGToken   string
	auditRGServer  string
)

// auditCmd is a help-only parent grouping the source/deps/package scoring
// commands and the saved-report viewer, so the related verbs share one
// namespace (mirrors the `policy` group).
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Score a source repo, its dependencies, or a single package; view a saved report",
	Long: `Parent command for the risk-guard scoring verbs:

  audit source   score the local source repo only (no dependency audit)
  audit deps     audit direct dependencies from an SBOM
  audit package  score a single package by its analysis-identifier key
  audit view     render a saved SARIF report exactly as the run that produced it

Run the full pipeline (source + SBOM + dependency audit) with the bare
'risk-guard <path>' command.`,
}

var auditDepsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Audit direct dependencies from an SBOM",
	Long: `Audit reads an SBOM produced by 'risk-guard sbom' and scores its
direct dependencies (depth=1 from the root component). With --sarif a merged
SARIF report (one Run per dependency) is written; without it a human-readable
findings summary is printed instead.

Examples:
  risk-guard audit deps --sbom sbom.spdx --list
  risk-guard audit deps --sbom sbom.spdx
  risk-guard audit deps --sbom sbom.cdx.json --sarif audit.sarif --jobs 8`,
	Args: cobra.NoArgs,
	RunE: runAudit,
}

func init() {
	registerSharedDAGFlags(auditDepsCmd)
	auditDepsCmd.Flags().StringVar(&auditSBOMFile, "sbom", "", "Path to SBOM file (SPDX 3.0 or CycloneDX 1.6 JSON)")
	auditDepsCmd.Flags().BoolVar(&auditList, "list", false, "List direct dependencies and exit")
	auditDepsCmd.Flags().StringVar(&sarifOutFile, "sarif", "", flagHelpSARIF)
	auditDepsCmd.Flags().IntVar(&auditJobs, "jobs", 4, flagHelpJobs)
	auditDepsCmd.Flags().StringVar(&policyOverride, "policy-override", "", flagHelpPolicyOverride)
	auditDepsCmd.Flags().StringVar(&policyDefault, "policy-default", "", flagHelpPolicyDefault)
	auditDepsCmd.Flags().StringVar(&auditMaxAge, "max-age", "48h", flagHelpMaxAge)
	auditDepsCmd.Flags().BoolVar(&auditNoCache, "no-cache", false, flagHelpNoCache)
	auditDepsCmd.Flags().BoolVar(&auditRiskGuard, "risk-guard", false, "Offload the audit: upload the SBOM to the Risk Guard server to score its dependencies")
	auditDepsCmd.Flags().StringVar(&auditRGCommit, "commit", "", "Commit SHA to associate the run with (default: HEAD); only with --risk-guard")
	auditDepsCmd.Flags().StringVar(&auditRGToken, "token", "", "GitHub token for the Risk Guard server (default: $RISK_GUARD_TOKEN, $GITHUB_TOKEN, or 'gh auth token'); only with --risk-guard")
	auditDepsCmd.Flags().StringVar(&auditRGServer, "server", "", "Risk Guard server base URL (default: $RISK_GUARD_URL or https://ossriskguard.app); only with --risk-guard")
	if err := auditDepsCmd.MarkFlagRequired("sbom"); err != nil {
		panic(fmt.Errorf("marking --sbom required: %w", err))
	}
	registerSummaryRenderFlags(auditDepsCmd, true)
	auditCmd.AddCommand(auditDepsCmd)
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, _ []string) error {
	raw, err := os.ReadFile(auditSBOMFile) //nolint:gosec // user-provided flag
	if err != nil {
		return fmt.Errorf("reading SBOM: %w", err)
	}
	deps, err := sbom.ReadDirectDepsWithLocations(raw)
	if err != nil {
		return fmt.Errorf("parsing SBOM: %w", err)
	}
	keys, locByKey := keysAndLocations(deps)

	if auditList {
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	}

	if auditRiskGuard {
		return uploadAuditToRiskGuard(cmd.Context(), resolveRepoRoot(summaryRepoRoot), raw)
	}

	if auditJobs < 1 {
		return fmt.Errorf("--jobs must be >= 1")
	}

	ctx, overridesHash, err := setupAuditContext(cmd, "")
	if err != nil {
		return err
	}

	// The audit command scores an SBOM only; there is no local-source scan, so
	// pass nil to omit the "findings in source" line.
	depViolations, failures, err := runPackageAudits(ctx, keys, locByKey, overridesHash, nil)
	if err != nil {
		return err
	}

	report, err := assembleReport(ctx, "audit", nil, depViolations, failures, locByKey)
	if err != nil {
		return err
	}
	// With --sarif, persist the merged report; without it, print the findings
	// summary to the terminal so a bare `audit deps` is still useful.
	if sarifOutFile != "" {
		return writeReport(report, sarifOutFile)
	}
	return renderReportSummary(report, summaryModeOverride, summaryGitHub, summaryGitLab, resolveRepoRoot(summaryRepoRoot))
}
