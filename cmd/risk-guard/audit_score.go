package main

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/observe"
	"github.com/Risk-Guard/oss-risk-guard/src/ui"
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
func scoreAll(ctx context.Context, keys []string, locByKey map[string]*models.LocationInfo, overridesHash string, checkMetadata []dag_builder.CheckInfo, jobs int, cc cacheConfig) ([]*violations.AnalysisViolations, []packageError, auditTotals, error) {
	type indexedResult struct {
		key      string
		analysis *violations.AnalysisViolations
		err      error
	}

	results := make([]indexedResult, 0, len(keys))
	var mu sync.Mutex
	var totals auditTotals
	var done int

	disp := ui.FromContext(ctx)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(jobs)

	for _, key := range keys {
		g.Go(func() error {
			// A phase span per package. The DAG executor reports each node it
			// runs underneath it, so the row tracks the real current activity
			// (fetching registry metadata, reading git history, …) instead of a
			// frozen label.
			analysis, cachedAge, scoreErr := withPhase2(gctx, key, func(pctx context.Context) (*violations.AnalysisViolations, time.Duration, error) {
				return scoreOneCached(pctx, key, overridesHash, checkMetadata, cc)
			})

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
			printProgress(disp, done, len(keys), key, fcount, scoreErr, cachedAge, locByKey[key])
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

// phaseStatus maps a scoring outcome onto the observer's vocabulary.
func phaseStatus(err error) observe.Status {
	if err != nil {
		return observe.StatusError
	}
	return observe.StatusOK
}

// withPhase runs fn under a phase span named name, passing it the span's
// context so nodes it runs report underneath the row. End is deferred, per the
// observe.Span contract, so a panic in fn cannot strand a live row; the span
// still ends the moment fn returns, before the caller's next phase begins.
func withPhase[T any](ctx context.Context, name string, fn func(context.Context) (T, error)) (T, error) {
	pctx, phase := observe.From(ctx).Begin(ctx, observe.Event{
		Kind: observe.KindPhase,
		Name: name,
	})
	var (
		v   T
		err error
	)
	defer func() { phase.End(phaseStatus(err), err) }()
	v, err = fn(pctx)
	return v, err
}

// withPhase2 is withPhase for work that yields two values alongside its error.
func withPhase2[A, B any](ctx context.Context, name string, fn func(context.Context) (A, B, error)) (A, B, error) {
	pctx, phase := observe.From(ctx).Begin(ctx, observe.Event{
		Kind: observe.KindPhase,
		Name: name,
	})
	var (
		a   A
		b   B
		err error
	)
	defer func() { phase.End(phaseStatus(err), err) }()
	a, b, err = fn(pctx)
	return a, b, err
}

// printProgress writes one completed-audit line through the UI so it scrolls
// cleanly above the in-flight rows; when rows are disabled the UI passes it
// straight through to stderr.
func printProgress(disp *ui.UI, done, total int, key string, findingCount int, scoreErr error, cachedAge time.Duration, loc *models.LocationInfo) {
	prefix := color.HiBlackString("[%d/%d]", done, total)
	var prov string
	if p := manifestProvenance(loc); p != "" {
		prov = "  " + color.HiBlackString("from %s", p)
	}
	var suffix string
	if cachedAge >= 0 {
		suffix = "  " + color.HiBlackString("(cached, %s ago)", roundDuration(cachedAge))
	}
	var status string
	switch {
	case scoreErr != nil:
		status = color.RedString("FAILED")
	case findingCount > 0:
		status = color.YellowString("%d findings", findingCount)
	default:
		status = color.GreenString("ok")
	}
	disp.Printf("%s %s  %s%s%s\n", prefix, key, status, prov, suffix)
}

// manifestProvenance renders the manifest file (and line) a dependency was
// declared in, e.g. "requirements.txt:3" — the "where did this come from"
// shown on each audit line. Returns "" when the SBOM gave no location.
func manifestProvenance(loc *models.LocationInfo) string {
	if loc == nil || loc.File == nil || *loc.File == "" {
		return ""
	}
	if loc.LineNumber != nil && *loc.LineNumber > 0 {
		return fmt.Sprintf("%s:%d", *loc.File, *loc.LineNumber)
	}
	return *loc.File
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
