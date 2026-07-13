package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setOverrideFlags sets the package-level flag globals runPolicyOverride reads
// and restores them after the test, so cases don't leak state into each other.
func setOverrideFlags(t *testing.T, reason, precedence string, force bool) {
	t.Helper()
	pr, pp, pf := overrideReason, overridePrecedence, overrideForce
	t.Cleanup(func() { overrideReason, overridePrecedence, overrideForce = pr, pp, pf })
	overrideReason, overridePrecedence, overrideForce = reason, precedence, force
}

func TestPolicyOverride_WritesSourceURL(t *testing.T) {
	dir := t.TempDir()
	setOverrideFlags(t, "npm metadata points at a dead fork", "force", false)

	err := runPolicyOverride(nil, []string{
		"package/npm/left-pad", "output.source_url", "https://github.com/stevemao/left-pad", dir,
	})
	if err != nil {
		t.Fatalf("runPolicyOverride: %v", err)
	}

	res, _, err := loadRepoPolicy(dir)
	if err != nil {
		t.Fatalf("loadRepoPolicy: %v", err)
	}
	ovs := res.Overrides["package/npm/left-pad"]
	if len(ovs) != 1 {
		t.Fatalf("got %d overrides, want 1: %+v", len(ovs), ovs)
	}
	o := ovs[0]
	if o.Path != "output.source_url" {
		t.Errorf("path = %q, want output.source_url", o.Path)
	}
	if o.Value != "https://github.com/stevemao/left-pad" {
		t.Errorf("value = %v, want the git URL", o.Value)
	}
	if o.Reason == "" {
		t.Errorf("reason not persisted")
	}
	// force is the default and is stored as an empty precedence.
	if o.Precedence != "" {
		t.Errorf("precedence = %q, want empty (force default)", o.Precedence)
	}
}

func TestPolicyOverride_FallbackPrecedencePersisted(t *testing.T) {
	dir := t.TempDir()
	setOverrideFlags(t, "gap-fill only", "fallback", false)

	if err := runPolicyOverride(nil, []string{
		"package/npm/x", "output.source_url", "https://example.com/repo", dir,
	}); err != nil {
		t.Fatalf("runPolicyOverride: %v", err)
	}
	res, _, err := loadRepoPolicy(dir)
	if err != nil {
		t.Fatalf("loadRepoPolicy: %v", err)
	}
	if got := res.Overrides["package/npm/x"][0].Precedence; got != "fallback" {
		t.Errorf("precedence = %q, want fallback", got)
	}
}

func TestPolicyOverride_ReasonRequired(t *testing.T) {
	dir := t.TempDir()
	setOverrideFlags(t, "  ", "force", false)

	err := runPolicyOverride(nil, []string{"package/npm/x", "output.source_url", "u", dir})
	if err == nil || !strings.Contains(err.Error(), "--reason is required") {
		t.Fatalf("want --reason error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, initFileName)); !os.IsNotExist(err) {
		t.Errorf(".risk-guard.yml should not have been written on validation failure (stat err: %v)", err)
	}
}

func TestPolicyOverride_RejectsNonOutputPath(t *testing.T) {
	dir := t.TempDir()
	setOverrideFlags(t, "r", "force", false)

	err := runPolicyOverride(nil, []string{"package/npm/x", "source_url", "u", dir})
	if err == nil || !strings.Contains(err.Error(), "output namespace") {
		t.Fatalf("want output-namespace error, got %v", err)
	}
}

func TestPolicyOverride_RejectsBadEntityKey(t *testing.T) {
	dir := t.TempDir()
	setOverrideFlags(t, "r", "force", false)

	err := runPolicyOverride(nil, []string{"npm/x", "output.source_url", "u", dir})
	if err == nil || !strings.Contains(err.Error(), "invalid entity key") {
		t.Fatalf("want invalid-entity-key error, got %v", err)
	}
}

func TestPolicyOverride_RejectsBadPrecedence(t *testing.T) {
	dir := t.TempDir()
	setOverrideFlags(t, "r", "sometimes", false)

	err := runPolicyOverride(nil, []string{"package/npm/x", "output.source_url", "u", dir})
	if err == nil || !strings.Contains(err.Error(), "invalid --precedence") {
		t.Fatalf("want invalid-precedence error, got %v", err)
	}
}

func TestPolicyOverride_ReplaceNeedsForce(t *testing.T) {
	dir := t.TempDir()

	setOverrideFlags(t, "first", "force", false)
	if err := runPolicyOverride(nil, []string{"package/npm/x", "output.source_url", "https://a.example/r", dir}); err != nil {
		t.Fatalf("first override: %v", err)
	}

	// Second write to the same key+path without --force must be refused.
	setOverrideFlags(t, "second", "force", false)
	err := runPolicyOverride(nil, []string{"package/npm/x", "output.source_url", "https://b.example/r", dir})
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want replace-needs-force error, got %v", err)
	}

	// With --force it replaces the value in place (still one entry).
	setOverrideFlags(t, "second", "force", true)
	if err := runPolicyOverride(nil, []string{"package/npm/x", "output.source_url", "https://b.example/r", dir}); err != nil {
		t.Fatalf("forced override: %v", err)
	}
	res, _, err := loadRepoPolicy(dir)
	if err != nil {
		t.Fatalf("loadRepoPolicy: %v", err)
	}
	ovs := res.Overrides["package/npm/x"]
	if len(ovs) != 1 {
		t.Fatalf("got %d overrides, want 1 after replace", len(ovs))
	}
	if ovs[0].Value != "https://b.example/r" {
		t.Errorf("value = %v, want the replacement URL", ovs[0].Value)
	}
}

func TestPolicyOverride_PreservesExistingOverrideEntries(t *testing.T) {
	dir := t.TempDir()

	setOverrideFlags(t, "first pkg", "force", false)
	if err := runPolicyOverride(nil, []string{"package/npm/a", "output.source_url", "https://a.example/r", dir}); err != nil {
		t.Fatalf("first override: %v", err)
	}
	setOverrideFlags(t, "second pkg", "force", false)
	if err := runPolicyOverride(nil, []string{"package/npm/b", "output.source_url", "https://b.example/r", dir}); err != nil {
		t.Fatalf("second override: %v", err)
	}

	res, _, err := loadRepoPolicy(dir)
	if err != nil {
		t.Fatalf("loadRepoPolicy: %v", err)
	}
	if len(res.Overrides["package/npm/a"]) != 1 || len(res.Overrides["package/npm/b"]) != 1 {
		t.Errorf("second write dropped the first package's override: %+v", res.Overrides)
	}
}
