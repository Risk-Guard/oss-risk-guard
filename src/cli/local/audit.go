package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"

	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
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
	Long: `Audit reads an SBOM produced by 'risk-guard-local sbom' and scores its
direct dependencies (depth=1 from the root component), emitting a merged SARIF
report with one Run per dependency.

Examples:
  risk-guard-local audit --sbom sbom.spdx --list
  risk-guard-local audit --sbom sbom.spdx --sarif audit.sarif
  risk-guard-local audit --sbom sbom.cdx.json --sarif audit.sarif --jobs 8`,
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
	ctx := cmd.Context()
	logger := ctxutil.GetLogger(ctx)

	raw, err := os.ReadFile(auditSBOMFile) //nolint:gosec // user-provided flag
	if err != nil {
		return fmt.Errorf("reading SBOM: %w", err)
	}

	deps, err := sbom.ReadDirectDepsWithLocations(raw)
	if err != nil {
		return fmt.Errorf("parsing SBOM: %w", err)
	}

	keys := make([]string, len(deps))
	locationByKey := make(map[string]*models.LocationInfo, len(deps))
	for i, d := range deps {
		keys[i] = d.Key
		if d.Location != nil {
			locationByKey[d.Key] = d.Location
		}
	}

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

	ctx, err = cache.InitializeCacheBackend(ctx)
	if err != nil {
		return err
	}
	ctx, err = storage.InitializeStorageBackend(ctx)
	if err != nil {
		return err
	}
	ctx, overridesHash, err := loadAndSetupOverrides(ctx, overridesFile)
	if err != nil {
		return err
	}
	cmd.SetContext(ctx)

	checkMetadata, _ := dag_builder.GetAllCheckMetadata(localdag.PackageBuilder)

	cacheCfg, err := buildCacheConfig(ctx, checkMetadata)
	if err != nil {
		return err
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

	runs, totals, err := scoreAll(ctx, keys, overridesHash, checkMetadata, auditJobs, cacheCfg, locationByKey)
	if err != nil {
		return err
	}

	report, err := sarif.New(sarif.Version210, true)
	if err != nil {
		return fmt.Errorf("creating SARIF report: %w", err)
	}
	for _, r := range runs {
		report.AddRun(r)
	}
	if err := os.MkdirAll(filepath.Dir(sarifOutFile), 0o750); err != nil {
		return fmt.Errorf("creating SARIF output directory: %w", err)
	}
	if err := report.WriteFile(sarifOutFile); err != nil {
		return fmt.Errorf("writing SARIF: %w", err)
	}
	logger.Info("wrote SARIF report", zap.String("path", sarifOutFile), zap.Int("runs", len(runs)))

	bold(os.Stderr, "\nWrote %d runs to %s\n", len(runs), sarifOutFile)
	fmt.Fprintf(os.Stderr, "  %s  %s  %s  %s\n",
		color.RedString("%d errors", totals.errors),
		color.YellowString("%d warnings", totals.warnings),
		color.CyanString("%d notes", totals.notes),
		color.HiBlackString("%d info", totals.info))
	if totals.audit > 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", color.RedString("%d packages failed to score", totals.audit))
	}
	if cacheCfg.enabled {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("%d/%d packages served from cache", totals.cached, len(runs)))
	}
	return nil
}
