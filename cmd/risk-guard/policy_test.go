package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"github.com/fatih/color"
)

func TestRenderEffectivePolicy_SeverityFirstAndContent(t *testing.T) {
	prev := color.NoColor
	t.Cleanup(func() { color.NoColor = prev })
	color.NoColor = true // assert on plain text

	pol := &policy.Policy{
		Version:  policy.CurrentVersion,
		Workflow: &policy.WorkflowConfig{Mode: policy.WorkflowModeNoFail},
		Severity: map[string]policy.SeverityValue{
			"category/critical": {Severity: policy.SeverityBlocking},
		},
		ExpectedFailures: map[string]policy.ExpectedFailureV2{
			"package/npm/lodash": {Checks: []string{"VULN_CHECK"}, Reason: "tracked"},
		},
	}
	out := renderEffectivePolicy("/repo", pol, true)

	sevIdx := strings.Index(out, "Severity rules")
	wfIdx := strings.Index(out, "Workflow")
	efIdx := strings.Index(out, "Expected failures")
	if sevIdx < 0 || wfIdx < 0 || efIdx < 0 {
		t.Fatalf("missing a section header:\n%s", out)
	}
	if sevIdx >= wfIdx || wfIdx >= efIdx {
		t.Errorf("sections out of order: severity=%d workflow=%d expected=%d", sevIdx, wfIdx, efIdx)
	}
	for _, want := range []string{"category/critical", "blocking", "no-fail", "package/npm/lodash", "VULN_CHECK", "tracked"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestAddPick(t *testing.T) {
	picked := map[string]map[string]struct{}{}
	addPick(picked, "package/npm/lodash", "VULN_CHECK")
	addPick(picked, "package/npm/lodash", "LICENSE_CHECK")
	addPick(picked, "package/npm/lodash", "VULN_CHECK") // duplicate is a no-op
	addPick(picked, "root", "SOURCE_NO_LICENSE")

	if len(picked["package/npm/lodash"]) != 2 {
		t.Errorf("lodash: got %d checks, want 2", len(picked["package/npm/lodash"]))
	}
	if _, ok := picked["root"]["SOURCE_NO_LICENSE"]; !ok {
		t.Errorf("root check not recorded")
	}
}

func TestMergeExpectedFailures_NilMapAndSort(t *testing.T) {
	pol := &policy.Policy{} // ExpectedFailures is nil
	picked := map[string]map[string]struct{}{
		"package/npm/lodash": {"VULN_CHECK": {}, "LICENSE_CHECK": {}},
	}
	mergeExpectedFailures(pol, picked, "r")

	got := pol.ExpectedFailures["package/npm/lodash"]
	want := []string{"LICENSE_CHECK", "VULN_CHECK"} // sorted
	if !reflect.DeepEqual(got.Checks, want) {
		t.Errorf("checks = %v, want %v", got.Checks, want)
	}
	if got.Reason != "r" {
		t.Errorf("reason = %q, want %q", got.Reason, "r")
	}
}

func TestMergeExpectedFailures_UnionsWithExisting(t *testing.T) {
	pol := &policy.Policy{
		ExpectedFailures: map[string]policy.ExpectedFailureV2{
			"package/npm/lodash": {Checks: []string{"VULN_CHECK"}, Reason: "hand written"},
		},
	}
	picked := map[string]map[string]struct{}{
		"package/npm/lodash": {"LICENSE_CHECK": {}, "VULN_CHECK": {}}, // VULN_CHECK already present
		"root":               {"SOURCE_NO_LICENSE": {}},
	}
	mergeExpectedFailures(pol, picked, "new reason")

	lodash := pol.ExpectedFailures["package/npm/lodash"]
	if !reflect.DeepEqual(lodash.Checks, []string{"LICENSE_CHECK", "VULN_CHECK"}) {
		t.Errorf("lodash checks = %v, want deduped+sorted", lodash.Checks)
	}
	if lodash.Reason != "hand written" {
		t.Errorf("existing reason must be preserved, got %q", lodash.Reason)
	}
	root := pol.ExpectedFailures["root"]
	if !reflect.DeepEqual(root.Checks, []string{"SOURCE_NO_LICENSE"}) {
		t.Errorf("root checks = %v", root.Checks)
	}
	if root.Reason != "new reason" {
		t.Errorf("new entity should get the supplied reason, got %q", root.Reason)
	}
}

func TestMergeExpectedFailures_EmptyPickedIsNoop(t *testing.T) {
	pol := &policy.Policy{}
	mergeExpectedFailures(pol, map[string]map[string]struct{}{}, "r")
	if pol.ExpectedFailures != nil {
		t.Errorf("empty picked must not allocate, got %v", pol.ExpectedFailures)
	}
}
