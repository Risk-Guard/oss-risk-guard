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
