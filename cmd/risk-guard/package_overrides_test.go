package main

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"
)

func findOverride(ovs []overridesEntry, path string) (overridesEntry, bool) {
	for _, o := range ovs {
		if o.Path == path {
			return o, true
		}
	}
	return overridesEntry{}, false
}

// overridesEntry mirrors the fields of overrides.Override we assert on, so the
// test reads independently of import aliasing.
type overridesEntry struct {
	Path       string
	Value      any
	Reason     string
	Precedence string
}

func toEntries(t *testing.T, key string, polOverrides map[string][]policy.PolicyOverride) []overridesEntry {
	t.Helper()
	out := packageOverridesFor(polOverrides, key)
	entries := make([]overridesEntry, 0, len(out))
	for _, o := range out {
		entries = append(entries, overridesEntry{Path: o.Path, Value: o.Value, Reason: o.Reason, Precedence: o.Precedence})
	}
	return entries
}

func TestPackageOverridesFor_BuiltinTypesWildcard(t *testing.T) {
	for _, key := range []string{
		"package/npm/@types/json5",
		"package/npm/@types/json5?version=2.2.0",
	} {
		entries := toEntries(t, key, nil)
		o, ok := findOverride(entries, "source_url")
		if !ok {
			t.Fatalf("key %q: expected built-in source_url override, got %+v", key, entries)
		}
		if o.Precedence != "fallback" {
			t.Errorf("key %q: expected precedence=fallback, got %q", key, o.Precedence)
		}
		if o.Value != "https://github.com/DefinitelyTyped/DefinitelyTyped" {
			t.Errorf("key %q: unexpected value %v", key, o.Value)
		}
	}
}

func TestPackageOverridesFor_NonTypesUnmatched(t *testing.T) {
	entries := toEntries(t, "package/npm/lodash?version=4.17.20", nil)
	if len(entries) != 0 {
		t.Errorf("expected no overrides for non-@types package, got %+v", entries)
	}
}

func TestPackageOverridesFor_UserOverrideWinsOverBuiltin(t *testing.T) {
	polOverrides := map[string][]policy.PolicyOverride{
		"package/npm/@types/json5": {
			{Path: "output.source_url", Value: "https://example.com/mine", Reason: "user correction"},
		},
	}
	entries := toEntries(t, "package/npm/@types/json5?version=2.2.0", polOverrides)

	count := 0
	for _, e := range entries {
		if e.Path == "source_url" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 source_url override (built-in deduped), got %d: %+v", count, entries)
	}
	o, _ := findOverride(entries, "source_url")
	if o.Value != "https://example.com/mine" {
		t.Errorf("expected user value to win, got %v", o.Value)
	}
	if o.Precedence != "" {
		t.Errorf("expected user override precedence empty (force), got %q", o.Precedence)
	}
}

func TestPackageOverridesFor_OverlappingPatternsDeterministicExactWins(t *testing.T) {
	// Two user patterns both match the package and both target source_url: an
	// exact key and an overlapping wildcard. The exact (more specific) key must
	// win every time, regardless of map-iteration order.
	polOverrides := map[string][]policy.PolicyOverride{
		"package/npm/react": {
			{Path: "output.source_url", Value: "https://github.com/facebook/react", Reason: "exact"},
		},
		"package/npm/re*": {
			{Path: "output.source_url", Value: "https://example.com/wildcard", Reason: "wildcard"},
		},
	}

	// Run repeatedly to surface any dependence on Go map ordering.
	for i := 0; i < 50; i++ {
		entries := toEntries(t, "package/npm/react?version=18.0.0", polOverrides)

		count := 0
		for _, e := range entries {
			if e.Path == "source_url" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("iter %d: expected exactly 1 source_url override, got %d: %+v", i, count, entries)
		}
		o, _ := findOverride(entries, "source_url")
		if o.Value != "https://github.com/facebook/react" {
			t.Fatalf("iter %d: expected exact key to win deterministically, got %v", i, o.Value)
		}
	}
}

func TestPackageOverridesFor_NonWildcardKeyMatchesVersionedKey(t *testing.T) {
	polOverrides := map[string][]policy.PolicyOverride{
		"package/npm/lodash": {
			{Path: "output.source_url", Value: "https://github.com/lodash/lodash", Reason: "fix"},
		},
	}
	entries := toEntries(t, "package/npm/lodash?version=4.17.20", polOverrides)
	o, ok := findOverride(entries, "source_url")
	if !ok {
		t.Fatalf("expected non-wildcard key to match versioned key, got %+v", entries)
	}
	if o.Value != "https://github.com/lodash/lodash" {
		t.Errorf("unexpected value %v", o.Value)
	}
}
