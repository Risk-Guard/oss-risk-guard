package main

import (
	"context"
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
	_, _, polOverrides, ok := policy.GetRootPolicy(ctx)
	if !ok || len(polOverrides) == 0 {
		return ctx, baseHash
	}

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
// the version-stripped key (init writes bare package keys). Built-in
// knownOverrides are merged in as well: user overrides win per target path, so a
// built-in fallback only fills a path the user has not already addressed.
func packageOverridesFor(polOverrides map[string][]policy.PolicyOverride, key string) []overrides.Override {
	userEntries := matchOverrideEntries(polOverrides, key)

	userPaths := make(map[string]bool, len(userEntries))
	for _, e := range userEntries {
		userPaths[strings.TrimPrefix(e.Path, "output.")] = true
	}

	// Built-ins first, then user entries: with per-path dedupe there is at most
	// one override per path, but ordering keeps the gap-filler intent explicit.
	var entries []policy.PolicyOverride
	for _, e := range matchOverrideEntries(knownOverrides, key) {
		if userPaths[strings.TrimPrefix(e.Path, "output.")] {
			continue
		}
		entries = append(entries, e)
	}
	entries = append(entries, userEntries...)
	if len(entries) == 0 {
		return nil
	}

	out := make([]overrides.Override, 0, len(entries))
	for _, e := range entries {
		out = append(out, overrides.Override{
			Path:       strings.TrimPrefix(e.Path, "output."),
			Value:      e.Value,
			Reason:     e.Reason,
			Precedence: e.Precedence,
		})
	}
	return out
}

// matchOverrideEntries collects every override whose key pattern matches the
// package key, testing both the full key and its version-stripped form so that
// non-wildcard keys keep matching versioned keys exactly as before.
func matchOverrideEntries(table map[string][]policy.PolicyOverride, key string) []policy.PolicyOverride {
	stripped := stripVersionQuery(key)
	var out []policy.PolicyOverride
	for pattern, items := range table {
		if policy.MatchesPattern(pattern, key) || (stripped != key && policy.MatchesPattern(pattern, stripped)) {
			out = append(out, items...)
		}
	}
	return out
}

// stripVersionQuery drops a trailing "?version=..." (or any query) from a
// package key, so "package/pypi/foo?version=1.2.3" matches an override written
// against "package/pypi/foo".
func stripVersionQuery(key string) string {
	base, _, _ := strings.Cut(key, "?")
	return base
}
