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
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit direct dependencies from an SBOM",
	Long: `Audit reads an SBOM produced by 'risk-guard sbom' and scores its
direct dependencies (depth=1 from the root component), emitting a merged SARIF
report with one Run per dependency.

Examples:
  risk-guard audit --sbom sbom.spdx --list
  risk-guard audit --sbom sbom.spdx --sarif audit.sarif
  risk-guard audit --sbom sbom.cdx.json --sarif audit.sarif --jobs 8`,
	Args: cobra.NoArgs,
	RunE: runAudit,
}

func init() {
	registerSharedDAGFlags(auditCmd)
	auditCmd.Flags().StringVar(&auditSBOMFile, "sbom", "", "Path to SBOM file (SPDX 3.0 or CycloneDX 1.6 JSON)")
	auditCmd.Flags().BoolVar(&auditList, "list", false, "List direct dependencies and exit")
	auditCmd.Flags().StringVar(&sarifOutFile, "sarif", "", "Output file for merged SARIF report (SARIF 2.1.0 JSON)")
	auditCmd.Flags().IntVar(&auditJobs, "jobs", 4, "Maximum number of packages to score in parallel")
	auditCmd.Flags().StringVar(&policyOverride, "policy-override", "", "Policy file that completely overrides all policy (YAML)")
	auditCmd.Flags().StringVar(&policyDefault, "policy-default", "", "Policy file to use as base instead of global default (YAML)")
	auditCmd.Flags().StringVar(&auditMaxAge, "max-age", "48h", "Maximum cache age (e.g. 30m, 48h, 2d). 0 disables caching")
	auditCmd.Flags().BoolVar(&auditNoCache, "no-cache", false, "Force fresh scoring; do not read or write the audit cache")
	if err := auditCmd.MarkFlagRequired("sbom"); err != nil {
		panic(fmt.Errorf("marking --sbom required: %w", err))
	}
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
	if sarifOutFile == "" {
		return fmt.Errorf("--sarif is required when not using --list")
	}
	if auditJobs < 1 {
		return fmt.Errorf("--jobs must be >= 1")
	}

	ctx, overridesHash, err := setupAuditContext(cmd)
	if err != nil {
		return err
	}

	auditRuns, err := runPackageAudits(ctx, keys, locByKey, overridesHash)
	if err != nil {
		return err
	}

	report, err := assembleReport(nil, auditRuns)
	if err != nil {
		return err
	}
	return writeReport(report, sarifOutFile)
}
