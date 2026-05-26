package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	commonsarif "github.com/Risk-Guard/oss-risk-guard/src/lib/common/sarif"

	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	dagcmd "github.com/Risk-Guard/oss-risk-guard/src/cmd/subcommands/dag"

	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
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

	keys, err := sbom.ReadDirectDeps(raw)
	if err != nil {
		return fmt.Errorf("parsing SBOM: %w", err)
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

	runs, totals, err := scoreAll(ctx, keys, overridesHash, checkMetadata, auditJobs, cacheCfg)
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

type auditTotals struct {
	errors, warnings, notes, info, audit, cached int
}

// scoreAll scores keys in bounded parallel (limit=jobs) and returns one SARIF
// Run per key, ordered by key for deterministic output. A failure scoring one
// package becomes a synthetic error Run; it does not abort siblings.
// Prints a per-package progress line to stderr as each package finishes.
func scoreAll(ctx context.Context, keys []string, overridesHash string, checkMetadata []dag_builder.CheckInfo, jobs int, cc cacheConfig) ([]*sarif.Run, auditTotals, error) {
	type indexedRun struct {
		key string
		run *sarif.Run
	}

	results := make([]indexedRun, 0, len(keys))
	var mu sync.Mutex
	var totals auditTotals
	var done int

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(jobs)

	for _, key := range keys {
		g.Go(func() error {
			run, cachedAge := scoreOneCached(gctx, key, overridesHash, checkMetadata, cc)
			counts, isAuditErr := summarizeRun(run)

			mu.Lock()
			results = append(results, indexedRun{key: key, run: run})
			done++
			totals.errors += counts.errors
			totals.warnings += counts.warnings
			totals.notes += counts.notes
			totals.info += counts.info
			if isAuditErr {
				totals.audit++
			}
			if cachedAge >= 0 {
				totals.cached++
			}
			printProgress(done, len(keys), key, counts, isAuditErr, cachedAge)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, totals, err
	}

	sort.Slice(results, func(i, j int) bool { return results[i].key < results[j].key })
	runs := make([]*sarif.Run, 0, len(results))
	for _, r := range results {
		runs = append(runs, r.run)
	}
	return runs, totals, nil
}

// summarizeRun counts findings by SARIF level in a Run and detects audit-time
// failures (synthesized AUDIT_ERROR runs).
func summarizeRun(run *sarif.Run) (counts auditTotals, isAuditError bool) {
	for _, res := range run.Results {
		if res.RuleID != nil && *res.RuleID == "AUDIT_ERROR" {
			isAuditError = true
		}
		lvl := ""
		if res.Level != nil {
			lvl = *res.Level
		}
		switch lvl {
		case "error":
			counts.errors++
		case "warning", "":
			counts.warnings++
		case "note":
			counts.notes++
		case "none":
			counts.info++
		}
	}
	return counts, isAuditError
}

func printProgress(done, total int, key string, counts auditTotals, isAuditError bool, cachedAge time.Duration) {
	prefix := color.HiBlackString("[%d/%d]", done, total)
	var suffix string
	if cachedAge >= 0 {
		suffix = "  " + color.HiBlackString("(cached, %s ago)", roundDuration(cachedAge))
	}
	switch {
	case isAuditError:
		fmt.Fprintf(os.Stderr, "%s %s  %s%s\n", prefix, key, color.RedString("FAILED"), suffix)
	case counts.errors > 0:
		fmt.Fprintf(os.Stderr, "%s %s  %s%s\n", prefix, key,
			color.RedString("%d errors, %d warnings, %d info", counts.errors, counts.warnings, counts.notes+counts.info), suffix)
	case counts.warnings > 0:
		fmt.Fprintf(os.Stderr, "%s %s  %s%s\n", prefix, key,
			color.YellowString("%d warnings, %d info", counts.warnings, counts.notes+counts.info), suffix)
	case counts.notes+counts.info > 0:
		fmt.Fprintf(os.Stderr, "%s %s  %s%s\n", prefix, key,
			color.HiBlackString("%d info", counts.notes+counts.info), suffix)
	default:
		fmt.Fprintf(os.Stderr, "%s %s  %s%s\n", prefix, key, color.GreenString("ok"), suffix)
	}
}

func scoreOne(ctx context.Context, key, overridesHash string, checkMetadata []dag_builder.CheckInfo) *sarif.Run {
	eco, name, version, err := parsePackageKey(key)
	if err != nil {
		return errorRun(name, key, err)
	}
	input := dag_impl.NewPackageInputWithVersion(eco, name, version, overridesHash)
	return scoreOneWithInput(ctx, key, name, input, checkMetadata)
}

// scoreOneWithInput runs the DAG + evaluator for a prebuilt Input. Used by
// the cached path so we can build the Input once (for the cache key) and then
// reuse it for scoring on a miss.
func scoreOneWithInput(ctx context.Context, key, name string, input dag_impl.Input, checkMetadata []dag_builder.CheckInfo) *sarif.Run {
	logger := ctxutil.GetLogger(ctx)

	resp, err := dagcmd.BuildAndRunDAG(ctx, input, localdag.PackageBuilder)
	if err != nil {
		logger.Warn("scoring failed", zap.String("key", key), zap.Error(err))
		return errorRun(name, key, fmt.Errorf("scoring package: %w", err))
	}

	result, err := evaluate(ctx, input, resp.Checks, policyOverride, policyDefault)
	if err != nil {
		logger.Warn("evaluation failed", zap.String("key", key), zap.Error(err))
		return errorRun(name, key, fmt.Errorf("evaluation: %w", err))
	}

	report, err := commonsarif.FromEvaluationResult(result, checkMetadata)
	if err != nil {
		logger.Warn("sarif conversion failed", zap.String("key", key), zap.Error(err))
		return errorRun(name, key, fmt.Errorf("sarif conversion: %w", err))
	}
	if len(report.Runs) == 0 {
		return errorRun(name, key, fmt.Errorf("sarif conversion produced no runs"))
	}
	return report.Runs[0]
}

// errorRun synthesizes a SARIF Run for a single audit-time failure so the user
// sees the package in the merged report alongside successful scorings.
func errorRun(pkgName, key string, scoreErr error) *sarif.Run {
	if pkgName == "" {
		pkgName = key
	}
	run := sarif.NewRunWithInformationURI("risk-guard", commonsarif.InformationURI)
	run.AddRule("AUDIT_ERROR").
		WithShortDescription(sarif.NewMultiformatMessageString("Failed to score package during audit"))

	res := run.CreateResultForRule("AUDIT_ERROR").
		WithLevel("error").
		WithMessage(sarif.NewTextMessage(fmt.Sprintf("failed to score %s: %v", key, scoreErr)))

	name := pkgName
	kind := "package"
	res.WithLocations([]*sarif.Location{
		sarif.NewLocation().WithLogicalLocations([]*sarif.LogicalLocation{{
			Name: &name,
			Kind: &kind,
		}}),
	})
	return run
}
