package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

type testFindingLoc struct {
	Package          string
	RuleID           string
	Level            string
	Message          string
	ShortDescription string
	File             string // physicalLocation URI; "" omits it
	Line             int    // startLine; 0 omits the region
}

func newTestReportLoc(t *testing.T, findings []testFindingLoc) *sarif.Report {
	t.Helper()
	report, err := sarif.New(sarif.Version210, true)
	if err != nil {
		t.Fatalf("sarif.New: %v", err)
	}
	run := sarif.NewRunWithInformationURI("risk-guard", "https://example.invalid")
	for _, f := range findings {
		rule := run.AddRule(f.RuleID)
		if f.ShortDescription != "" {
			rule.WithShortDescription(sarif.NewMultiformatMessageString(f.ShortDescription))
		}
		res := run.CreateResultForRule(f.RuleID).
			WithLevel(f.Level).
			WithMessage(sarif.NewTextMessage(f.Message))
		pkgName := f.Package
		kind := "package"
		loc := sarif.NewLocation().WithLogicalLocations([]*sarif.LogicalLocation{{
			Name: &pkgName,
			Kind: &kind,
		}})
		if f.File != "" {
			phys := sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(f.File))
			if f.Line > 0 {
				phys = phys.WithRegion(sarif.NewSimpleRegion(f.Line, f.Line))
			}
			loc.WithPhysicalLocation(phys)
		}
		res.WithLocations([]*sarif.Location{loc})
	}
	report.AddRun(run)
	return report
}

func renderGitLabIssues(t *testing.T, report *sarif.Report, level string, packages []string, repoRoot string) ([]codeClimateIssue, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	if err := renderGitLab(&out, &errBuf, report, level, packages, repoRoot); err != nil {
		t.Fatalf("renderGitLab: %v", err)
	}
	var issues []codeClimateIssue
	if err := json.Unmarshal(out.Bytes(), &issues); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	return issues, errBuf.String()
}

func TestGitlabSeverity_Mapping(t *testing.T) {
	cases := []struct{ level, want string }{
		{levelError, "critical"},
		{levelWarning, "major"},
		{levelNote, "minor"},
		{levelInfo, "info"},
		{"unknown", "info"},
	}
	for _, c := range cases {
		if got := gitlabSeverity(c.level); got != c.want {
			t.Errorf("gitlabSeverity(%q) = %q, want %q", c.level, got, c.want)
		}
	}
}

func TestRenderGitLab_ShapeAndRequiredFields(t *testing.T) {
	report := newTestReportLoc(t, []testFindingLoc{
		{Package: "package/npm/lodash?version=4.17.20", RuleID: "STALE", Level: "error", Message: "stale release", ShortDescription: "Stale", File: "package.json", Line: 42},
		{Package: "package/npm/express", RuleID: "NO_LICENSE", Level: "warning", Message: "no license", File: "package.json", Line: 7},
	})
	issues, _ := renderGitLabIssues(t, report, "all", nil, "")

	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d: %#v", len(issues), issues)
	}
	validSeverity := map[string]bool{"info": true, "minor": true, "major": true, "critical": true, "blocker": true}
	for _, is := range issues {
		if is.Description == "" {
			t.Errorf("issue missing description: %#v", is)
		}
		if is.CheckName == "" {
			t.Errorf("issue missing check_name: %#v", is)
		}
		if is.Fingerprint == "" {
			t.Errorf("issue missing fingerprint: %#v", is)
		}
		if !validSeverity[is.Severity] {
			t.Errorf("invalid severity %q: %#v", is.Severity, is)
		}
		if is.Location.Path == "" {
			t.Errorf("issue missing location.path: %#v", is)
		}
		if is.Location.Lines.Begin <= 0 {
			t.Errorf("location.lines.begin must be > 0, got %d: %#v", is.Location.Lines.Begin, is)
		}
	}
	// The error finding's subject should lead the description, mirroring GitHub.
	var found bool
	for _, is := range issues {
		if is.CheckName == "STALE" {
			found = true
			if !strings.Contains(is.Description, "lodash@4.17.20 (npm)") {
				t.Errorf("expected subject in description, got %q", is.Description)
			}
			if is.Severity != "critical" {
				t.Errorf("error finding should map to critical, got %q", is.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("STALE finding not present: %#v", issues)
	}
}

func TestRenderGitLab_FingerprintStableAndUnique(t *testing.T) {
	f1 := codeClimateFingerprint("package/npm/lodash", "STALE", "package.json", 42)
	f2 := codeClimateFingerprint("package/npm/lodash", "STALE", "package.json", 42)
	if f1 != f2 {
		t.Errorf("fingerprint not stable: %q != %q", f1, f2)
	}
	f3 := codeClimateFingerprint("package/npm/lodash", "STALE", "package.json", 43)
	if f1 == f3 {
		t.Errorf("fingerprint should differ when line differs")
	}
	f4 := codeClimateFingerprint("package/npm/express", "STALE", "package.json", 42)
	if f1 == f4 {
		t.Errorf("fingerprint should differ when package differs")
	}
}

func TestRenderGitLab_RelativizesAbsolutePath(t *testing.T) {
	report := newTestReportLoc(t, []testFindingLoc{
		{Package: "package/npm/lodash", RuleID: "R", Level: "error", Message: "m", File: "/repo/src/package.json", Line: 3},
	})
	issues, _ := renderGitLabIssues(t, report, "all", nil, "/repo")
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].Location.Path != "src/package.json" {
		t.Errorf("expected relativized path src/package.json, got %q", issues[0].Location.Path)
	}
}

func TestRenderGitLab_SkipsPathlessFindingWithWarning(t *testing.T) {
	report := newTestReportLoc(t, []testFindingLoc{
		{Package: "package/npm/lodash", RuleID: "HASLOC", Level: "error", Message: "m", File: "package.json", Line: 5},
		{Package: "package/npm/express", RuleID: "NOLOC", Level: "error", Message: "m"}, // no File
	})
	issues, warnOut := renderGitLabIssues(t, report, "all", nil, "")
	if len(issues) != 1 || issues[0].CheckName != "HASLOC" {
		t.Fatalf("expected only the located finding, got %#v", issues)
	}
	if !strings.Contains(warnOut, "no file location") {
		t.Errorf("expected warning about skipped pathless finding, got %q", warnOut)
	}
}

func TestRenderGitLab_SkipsRepoRootAnchoredFinding(t *testing.T) {
	report := newTestReportLoc(t, []testFindingLoc{
		{Package: "package/npm/lodash", RuleID: "HASLOC", Level: "error", Message: "m", File: "package.json", Line: 5},
		{Package: "package/npm/express", RuleID: "ROOTANCHOR", Level: "error", Message: "m", File: "."}, // RepoRootURI
	})
	issues, warnOut := renderGitLabIssues(t, report, "all", nil, "")
	if len(issues) != 1 || issues[0].CheckName != "HASLOC" {
		t.Fatalf("expected only the located finding, got %#v", issues)
	}
	if !strings.Contains(warnOut, "no file location") {
		t.Errorf("expected warning about skipped root-anchored finding, got %q", warnOut)
	}
}

func TestRenderGitLab_DefaultsBeginToOneWhenNoLine(t *testing.T) {
	report := newTestReportLoc(t, []testFindingLoc{
		{Package: "package/npm/lodash", RuleID: "R", Level: "warning", Message: "m", File: "Gemfile"},
	})
	issues, _ := renderGitLabIssues(t, report, "all", nil, "")
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].Location.Lines.Begin != 1 {
		t.Errorf("expected begin defaulted to 1, got %d", issues[0].Location.Lines.Begin)
	}
}

func TestRenderGitLab_LevelFilter(t *testing.T) {
	report := newTestReportLoc(t, []testFindingLoc{
		{Package: "p1", RuleID: "R1", Level: "error", Message: "e", File: "a.json", Line: 1},
		{Package: "p2", RuleID: "R2", Level: "warning", Message: "w", File: "b.json", Line: 1},
	})
	issues, _ := renderGitLabIssues(t, report, "error", nil, "")
	if len(issues) != 1 || issues[0].CheckName != "R1" {
		t.Errorf("expected only error-level finding, got %#v", issues)
	}
}

func TestRenderGitLab_EmptyReportIsEmptyArray(t *testing.T) {
	report := newTestReportLoc(t, nil)
	var out, errBuf bytes.Buffer
	if err := renderGitLab(&out, &errBuf, report, "all", nil, ""); err != nil {
		t.Fatalf("renderGitLab: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "[]" {
		t.Errorf("expected empty array [], got %q", got)
	}
}
