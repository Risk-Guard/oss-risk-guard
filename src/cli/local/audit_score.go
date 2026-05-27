package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	commonsarif "github.com/Risk-Guard/oss-risk-guard/src/lib/common/sarif"

	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	dagcmd "github.com/Risk-Guard/oss-risk-guard/src/cmd/subcommands/dag"

	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type auditTotals struct {
	errors, warnings, notes, info, audit, cached int
}

// scoreAll scores keys in bounded parallel (limit=jobs) and returns one SARIF
// Run per key, ordered by key for deterministic output. A failure scoring one
// package becomes a synthetic error Run; it does not abort siblings.
// Prints a per-package progress line to stderr as each package finishes.
//
// locationByKey is consulted to stamp result.locations[].physicalLocation onto
// every Run.Results entry whose key is present. This happens AFTER scoring
// (and after any cache lookup) so the audit cache stays consumer-location
// agnostic: identical analysis is reused across consumers that declared the
// dep at different manifest lines.
func scoreAll(ctx context.Context, keys []string, overridesHash string, checkMetadata []dag_builder.CheckInfo, jobs int, cc cacheConfig, locationByKey map[string]*models.LocationInfo) ([]*sarif.Run, auditTotals, error) {
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
		if r.run.AutomationDetails == nil {
			r.run.WithAutomationDetails(sarif.NewRunAutomationDetails().WithID(r.key))
		}
		if loc, ok := locationByKey[r.key]; ok && loc != nil {
			injectPhysicalLocation(r.run, loc)
		}
		runs = append(runs, r.run)
	}
	return runs, totals, nil
}

// injectPhysicalLocation walks every result in run and sets the first location's
// physicalLocation to point at loc.File (and loc.LineNumber when present).
// Overwrites any existing physicalLocation so re-runs with a moved manifest
// line reflect the new position. Called after scoreOneCached so the on-disk
// audit cache stays free of consumer-side location metadata.
func injectPhysicalLocation(run *sarif.Run, loc *models.LocationInfo) {
	if run == nil || loc == nil || loc.File == nil {
		return
	}
	for _, res := range run.Results {
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
