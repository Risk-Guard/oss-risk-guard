package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	dagcmd "github.com/Risk-Guard/oss-risk-guard/src/cmd/subcommands/dag"

	"github.com/fatih/color"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// packageError captures a per-package scoring failure so it can be surfaced
// in the merged report after grading without polluting the cached violations.
type packageError struct {
	Key  string
	Name string
	Err  error
}

type auditTotals struct {
	scored, failed, cached int
	findings               int
}

// scoreAll scores keys in bounded parallel (limit=jobs). Returns one
// AnalysisViolations per successfully scored key (ordered by key) plus a
// separate slice of per-key failures. A failure does not abort siblings.
func scoreAll(ctx context.Context, keys []string, overridesHash string, checkMetadata []dag_builder.CheckInfo, jobs int, cc cacheConfig) ([]*violations.AnalysisViolations, []packageError, auditTotals, error) {
	type indexedResult struct {
		key      string
		analysis *violations.AnalysisViolations
		err      error
	}

	results := make([]indexedResult, 0, len(keys))
	var mu sync.Mutex
	var totals auditTotals
	var done int

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(jobs)

	for _, key := range keys {
		g.Go(func() error {
			analysis, cachedAge, scoreErr := scoreOneCached(gctx, key, overridesHash, checkMetadata, cc)

			mu.Lock()
			results = append(results, indexedResult{key: key, analysis: analysis, err: scoreErr})
			done++
			fcount := 0
			if analysis != nil {
				fcount = len(analysis.Violations)
			}
			if scoreErr != nil {
				totals.failed++
			} else {
				totals.scored++
				totals.findings += fcount
			}
			if cachedAge >= 0 {
				totals.cached++
			}
			printProgress(done, len(keys), key, fcount, scoreErr, cachedAge)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, totals, err
	}

	sort.Slice(results, func(i, j int) bool { return results[i].key < results[j].key })
	analyses := make([]*violations.AnalysisViolations, 0, len(results))
	var failures []packageError
	for _, r := range results {
		if r.err != nil {
			_, name, _, _ := parsePackageKey(r.key)
			if name == "" {
				name = r.key
			}
			failures = append(failures, packageError{Key: r.key, Name: name, Err: r.err})
			continue
		}
		if r.analysis != nil {
			analyses = append(analyses, r.analysis)
		}
	}
	return analyses, failures, totals, nil
}

func printProgress(done, total int, key string, findingCount int, scoreErr error, cachedAge time.Duration) {
	prefix := color.HiBlackString("[%d/%d]", done, total)
	var suffix string
	if cachedAge >= 0 {
		suffix = "  " + color.HiBlackString("(cached, %s ago)", roundDuration(cachedAge))
	}
	switch {
	case scoreErr != nil:
		fmt.Fprintf(os.Stderr, "%s %s  %s%s\n", prefix, key, color.RedString("FAILED"), suffix)
	case findingCount > 0:
		fmt.Fprintf(os.Stderr, "%s %s  %s%s\n", prefix, key,
			color.YellowString("%d findings", findingCount), suffix)
	default:
		fmt.Fprintf(os.Stderr, "%s %s  %s%s\n", prefix, key, color.GreenString("ok"), suffix)
	}
}

func scoreOne(ctx context.Context, key, overridesHash string, checkMetadata []dag_builder.CheckInfo) (*violations.AnalysisViolations, error) {
	eco, name, version, err := parsePackageKey(key)
	if err != nil {
		return nil, err
	}
	input := dag_impl.NewPackageInputWithVersion(eco, name, version, overridesHash)
	return scoreOneWithInput(ctx, key, name, input, checkMetadata)
}

// scoreOneWithInput runs the DAG and extracts the raw violations for a
// prebuilt Input. No grading or SARIF conversion happens here — that is the
// job of the merge step, which applies the rulebook once across every
// dep's violations.
func scoreOneWithInput(ctx context.Context, key, _ string, input dag_impl.Input, _ []dag_builder.CheckInfo) (*violations.AnalysisViolations, error) {
	logger := ctxutil.GetLogger(ctx)

	resp, err := dagcmd.BuildAndRunDAG(ctx, input, localdag.PackageBuilder)
	if err != nil {
		logger.Warn("scoring failed", zap.String("key", key), zap.Error(err))
		return nil, fmt.Errorf("scoring package: %w", err)
	}

	return extractAnalysisViolations(input, resp.Checks), nil
}
