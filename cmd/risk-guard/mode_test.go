package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

func TestResolveWorkflowMode_OverrideBeatsFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, policy.PolicyFileName),
		[]byte("version: 2\nworkflow:\n  mode: active\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveWorkflowMode("silent", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != policy.WorkflowModeSilent {
		t.Errorf("override should win, got %q", got)
	}
}

func TestResolveWorkflowMode_FromFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, policy.PolicyFileName),
		[]byte("version: 2\nworkflow:\n  mode: silent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveWorkflowMode("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != policy.WorkflowModeSilent {
		t.Errorf("expected silent from file, got %q", got)
	}
}

func TestResolveWorkflowMode_DefaultsToActive(t *testing.T) {
	got, err := resolveWorkflowMode("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got != policy.WorkflowModeActive {
		t.Errorf("missing policy file should default to active, got %q", got)
	}
}

func TestResolveWorkflowMode_RejectsInvalidOverride(t *testing.T) {
	if _, err := resolveWorkflowMode("loud", ""); err == nil {
		t.Errorf("expected error for invalid mode")
	}
}

// Typos in .risk-guard.yml previously slipped through LoadFullFromBytes (the
// field is a string alias). resolveWorkflowMode must reject them so blocking
// findings still fail the build instead of being silently downgraded.
func TestResolveWorkflowMode_RejectsTypoInFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, policy.PolicyFileName),
		[]byte("version: 2\nworkflow:\n  mode: silnt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveWorkflowMode("", dir); err == nil {
		t.Errorf("expected error for typo in workflow.mode")
	}
}

func TestResolveWorkflowMode_AcceptsNoFail(t *testing.T) {
	got, err := resolveWorkflowMode("no-fail", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != policy.WorkflowModeNoFail {
		t.Errorf("got %q, want no-fail", got)
	}
}

func TestModeBehaviors(t *testing.T) {
	cases := []struct {
		mode             policy.WorkflowMode
		wantAnnotations  bool
		wantFailBlocking bool
	}{
		{policy.WorkflowModeActive, true, true},
		{policy.WorkflowModeNoFail, true, false},
		{policy.WorkflowModeSilent, false, false},
		{policy.WorkflowModeDisabled, false, false},
	}
	for _, c := range cases {
		t.Run(string(c.mode), func(t *testing.T) {
			if got := emitsAnnotations(c.mode); got != c.wantAnnotations {
				t.Errorf("emitsAnnotations: got %v, want %v", got, c.wantAnnotations)
			}
			if got := failsOnBlocking(c.mode); got != c.wantFailBlocking {
				t.Errorf("failsOnBlocking: got %v, want %v", got, c.wantFailBlocking)
			}
		})
	}
}

func TestRunAllDisplayMode_GatesByEffectiveMode(t *testing.T) {
	prev := runAllGitHub
	t.Cleanup(func() { runAllGitHub = prev })

	cases := []struct {
		name   string
		github bool
		mode   policy.WorkflowMode
		want   DisplayMode
	}{
		{"no --github, any mode", false, policy.WorkflowModeActive, DisplayNone},
		{"--github + active emits", true, policy.WorkflowModeActive, DisplayGitHub},
		{"--github + no-fail emits", true, policy.WorkflowModeNoFail, DisplayGitHub},
		{"--github + silent suppresses", true, policy.WorkflowModeSilent, DisplayNone},
		{"--github + disabled suppresses", true, policy.WorkflowModeDisabled, DisplayNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runAllGitHub = c.github
			if got := runAllDisplayMode(c.mode); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestReportHasErrorLevel(t *testing.T) {
	mkLevel := func(s string) *string { return &s }
	mkRunWithLevel := func(level string) *sarif.Run {
		run := sarif.NewRun(*sarif.NewSimpleTool("t"))
		run.Results = []*sarif.Result{{Level: mkLevel(level)}}
		return run
	}

	cases := []struct {
		name   string
		report *sarif.Report
		want   bool
	}{
		{"nil report", nil, false},
		{"no runs", &sarif.Report{}, false},
		{"warnings only", &sarif.Report{Runs: []*sarif.Run{mkRunWithLevel("warning")}}, false},
		{"one error", &sarif.Report{Runs: []*sarif.Run{mkRunWithLevel("error")}}, true},
		{"mixed levels", &sarif.Report{Runs: []*sarif.Run{
			mkRunWithLevel("warning"),
			mkRunWithLevel("error"),
		}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reportHasErrorLevel(c.report); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestCountErrorLevel(t *testing.T) {
	mkLevel := func(s string) *string { return &s }
	mkRun := func(levels ...string) *sarif.Run {
		run := sarif.NewRun(*sarif.NewSimpleTool("t"))
		for _, l := range levels {
			run.Results = append(run.Results, &sarif.Result{Level: mkLevel(l)})
		}
		return run
	}

	cases := []struct {
		name   string
		report *sarif.Report
		want   int
	}{
		{"nil report", nil, 0},
		{"warnings only", &sarif.Report{Runs: []*sarif.Run{mkRun("warning", "note")}}, 0},
		{"single error", &sarif.Report{Runs: []*sarif.Run{mkRun("error")}}, 1},
		{"errors across runs", &sarif.Report{Runs: []*sarif.Run{
			mkRun("error", "warning"),
			mkRun("error", "error", "none"),
		}}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countErrorLevel(c.report); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}
