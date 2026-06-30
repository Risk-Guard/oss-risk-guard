package main

import (
	"context"
	"maps"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/overrides"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"go.uber.org/zap"
)

// packageOverrideContext applies the repo policy's per-package overrides for a
// single package key, returning a derived context carrying an override Store and
// the overrides hash used for cache keying.
//
// This is the point where .risk-guard.yml `overrides:` reach a package audit:
// early, before the package DAG runs, so a corrected output.source_url actually
// re-resolves the repository instead of only rewriting the displayed value. The
// hash flows into the package Input's AnalysisIdentifier, so an overridden audit
// gets its own cache entry and never reuses a non-overridden result.
//
// Returns (ctx, baseHash) unchanged when there are no overrides for this package.
func packageOverrideContext(ctx context.Context, key, baseHash string) (context.Context, string) {
	// polOverrides may be nil/empty when there is no .risk-guard.yml override
	// table; built-in knownOverrides are still merged in by packageOverridesFor,
	// so do not bail out here on an empty user table.
	_, _, polOverrides, _ := policy.GetRootPolicy(ctx)

	ovs := packageOverridesFor(polOverrides, key)
	if len(ovs) == 0 {
		return ctx, baseHash
	}

	hash, err := overrides.Hash(ovs)
	if err != nil {
		// A hash failure must not silently reuse a non-overridden cache entry:
		// fall back to disabling cache reuse for this package by leaving the
		// hash empty would do the opposite, so surface it and proceed with the
		// override applied (correctness over cache isolation).
		ctxutil.GetLogger(ctx).Warn("hashing package overrides failed; cache may not isolate this override",
			zap.String("key", key), zap.Error(err))
	}
	return overrides.SetStore(ctx, overrides.NewStore(ovs)), hash
}

// packageOverridesFor returns the overrides that apply to a package key,
// translating policy overrides into the engine's override form. Policy override
// paths are namespaced under the output object (e.g. "output.source_url"); the
// nodes that consume them key on the bare field name ("source_url"), so the
// leading "output." is stripped here.
//
// Override keys are matched as patterns via policy.MatchesPattern (supporting the
// same `*` wildcard as severity/expected_failures), against both the full key and
// the version-stripped key (init writes bare package keys). Each table is first
// collapsed to a single winner per target path (see dedupeByPath) so overlapping
// patterns resolve deterministically rather than by map-iteration order. Built-in
// knownOverrides are then merged in: user overrides win per target path, so a
// built-in fallback only fills a path the user has not already addressed.
func packageOverridesFor(polOverrides map[string][]policy.PolicyOverride, key string) []overrides.Override {
	userByPath := dedupeByPath(matchOverrideEntries(polOverrides, key))
	builtinByPath := dedupeByPath(matchOverrideEntries(knownOverrides, key))

	merged := make(map[string]policy.PolicyOverride, len(userByPath)+len(builtinByPath))
	maps.Copy(merged, builtinByPath)
	maps.Copy(merged, userByPath)
	if len(merged) == 0 {
		return nil
	}

	paths := make([]string, 0, len(merged))
	for path := range merged {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	out := make([]overrides.Override, 0, len(paths))
	for _, path := range paths {
		e := merged[path]
		out = append(out, overrides.Override{
			Path:       path,
			Value:      e.Value,
			Reason:     e.Reason,
			Precedence: e.Precedence,
		})
	}
	return out
}

// matchedOverride pairs an override with the table key (pattern) it matched
// through, so dedupeByPath can rank overlapping matches by pattern specificity.
type matchedOverride struct {
	pattern  string
	override policy.PolicyOverride
}

// matchOverrideEntries collects every override whose key pattern matches the
// package key, testing both the full key and its version-stripped form so that
// non-wildcard keys keep matching versioned keys exactly as before.
func matchOverrideEntries(table map[string][]policy.PolicyOverride, key string) []matchedOverride {
	stripped := stripVersionQuery(key)
	var out []matchedOverride
	for pattern, items := range table {
		if policy.MatchesPattern(pattern, key) || (stripped != key && policy.MatchesPattern(pattern, stripped)) {
			for _, e := range items {
				out = append(out, matchedOverride{pattern: pattern, override: e})
			}
		}
	}
	return out
}

// dedupeByPath collapses overrides that target the same output path to a single
// winner, keyed by the bare (output.-stripped) path. When more than one pattern
// matches the package key for the same path, the most specific pattern wins (see
// moreSpecific), so the applied override never depends on map-iteration order.
func dedupeByPath(matched []matchedOverride) map[string]policy.PolicyOverride {
	best := make(map[string]matchedOverride, len(matched))
	for _, m := range matched {
		path := strings.TrimPrefix(m.override.Path, "output.")
		if cur, ok := best[path]; !ok || moreSpecific(m.pattern, cur.pattern) {
			best[path] = m
		}
	}
	out := make(map[string]policy.PolicyOverride, len(best))
	for path, m := range best {
		out[path] = m.override
	}
	return out
}

// moreSpecific reports whether pattern a should win over pattern b when both
// match the same key and target the same path. An exact (wildcard-free) pattern
// beats a wildcard; otherwise the longer literal pattern wins, with a
// lexicographic tiebreak so the result is fully deterministic.
func moreSpecific(a, b string) bool {
	aWild, bWild := strings.Contains(a, "*"), strings.Contains(b, "*")
	if aWild != bWild {
		return !aWild
	}
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a < b
}

// stripVersionQuery drops a trailing "?version=..." (or any query) from a
// package key, so "package/pypi/foo?version=1.2.3" matches an override written
// against "package/pypi/foo".
func stripVersionQuery(key string) string {
	base, _, _ := strings.Cut(key, "?")
	return base
}
