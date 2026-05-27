package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

type testFinding struct {
	Package          string
	RuleID           string
	Level            string
	Message          string
	ShortDescription string
}

func newTestReport(t *testing.T, findings []testFinding) *sarif.Report {
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
		res.WithLocations([]*sarif.Location{loc})
	}
	report.AddRun(run)
	return report
}

func TestRenderAudit_GroupsSortsAndUsesRuleTitle(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "package/npm/lodash?version=4.17.20", RuleID: "RULE_B", Level: "warning", Message: "warn message", ShortDescription: "Warn title"},
		{Package: "package/npm/lodash?version=4.17.20", RuleID: "RULE_A", Level: "error", Message: "err message\nsecond line", ShortDescription: "Err title"},
		{Package: "package/npm/express", RuleID: "RULE_C", Level: "none", Message: "info message", ShortDescription: "Info title"},
	})

	var buf bytes.Buffer
	if err := renderAudit(&buf, report, "all", nil); err != nil {
		t.Fatalf("renderAudit: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "express (npm)") {
		t.Errorf("expected human package name \"express (npm)\" in output:\n%s", out)
	}
	if !strings.Contains(out, "lodash@4.17.20 (npm)") {
		t.Errorf("expected versioned package name \"lodash@4.17.20 (npm)\" in output:\n%s", out)
	}
	if !strings.Contains(out, "ERROR") || !strings.Contains(out, "Err title") {
		t.Errorf("expected ERROR level + rule title in output:\n%s", out)
	}
	if !strings.Contains(out, "INFO") {
		t.Errorf("expected INFO (mapped from none) in output:\n%s", out)
	}
	if !strings.Contains(out, "second line") {
		t.Errorf("expected multi-line message to be preserved:\n%s", out)
	}

	expressIdx := strings.Index(out, "express (npm)")
	lodashIdx := strings.Index(out, "lodash@4.17.20 (npm)")
	if expressIdx > lodashIdx {
		t.Errorf("expected express before lodash, got:\n%s", out)
	}

	errIdx := strings.Index(out, "RULE_A")
	warnIdx := strings.Index(out, "RULE_B")
	if errIdx < 0 || warnIdx < 0 || errIdx > warnIdx {
		t.Errorf("expected error before warning under lodash, got:\n%s", out)
	}
}

func TestRenderAudit_LevelFilter(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "package/npm/lodash", RuleID: "RULE_A", Level: "error", Message: "err"},
		{Package: "package/npm/lodash", RuleID: "RULE_B", Level: "warning", Message: "warn"},
	})

	var buf bytes.Buffer
	if err := renderAudit(&buf, report, "error", nil); err != nil {
		t.Fatalf("renderAudit: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "RULE_A") {
		t.Errorf("expected RULE_A in error-filtered output: %s", out)
	}
	if strings.Contains(out, "RULE_B") {
		t.Errorf("did not expect RULE_B in error-filtered output: %s", out)
	}
}

func TestRenderAudit_PackageFilter(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "lodash", RuleID: "RULE_A", Level: "error", Message: "err"},
		{Package: "express", RuleID: "RULE_B", Level: "error", Message: "err"},
	})

	var buf bytes.Buffer
	if err := renderAudit(&buf, report, "all", []string{"lodash"}); err != nil {
		t.Fatalf("renderAudit: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "lodash") {
		t.Errorf("expected lodash: %s", out)
	}
	if strings.Contains(out, "express") {
		t.Errorf("did not expect express: %s", out)
	}
}

func TestRenderAudit_EmptyReport(t *testing.T) {
	report := newTestReport(t, nil)
	var buf bytes.Buffer
	if err := renderAudit(&buf, report, "all", nil); err != nil {
		t.Fatalf("renderAudit: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "no findings" {
		t.Errorf("expected \"no findings\", got %q", got)
	}
}

func TestRenderAudit_InvalidLevel(t *testing.T) {
	report := newTestReport(t, nil)
	var buf bytes.Buffer
	if err := renderAudit(&buf, report, "critical", nil); err == nil {
		t.Fatalf("expected error for invalid level")
	}
}

func TestRenderAudit_HeaderOmitsZeroCounts(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "lodash", RuleID: "RULE_A", Level: "error", Message: "err"},
	})
	var buf bytes.Buffer
	if err := renderAudit(&buf, report, "all", nil); err != nil {
		t.Fatalf("renderAudit: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 error") {
		t.Errorf("expected \"1 error\" in header: %s", out)
	}
	if strings.Contains(out, "0 warning") || strings.Contains(out, "0 note") || strings.Contains(out, "0 info") {
		t.Errorf("expected zero-counts to be omitted: %s", out)
	}
}

func TestGithubEscapeMessage(t *testing.T) {
	in := "line1\nline2\rwith, comma: colon 50% off"
	got := githubEscapeMessage(in)
	want := "line1%0Aline2%0Dwith%2C comma%3A colon 50%25 off"
	if got != want {
		t.Errorf("escape mismatch:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestGithubEscapeTitle_CollapsesNewlines(t *testing.T) {
	got := githubEscapeTitle("line1\nline2\r\nline3")
	// Newlines should be spaces (not %0A) so the title stays single-line.
	if strings.Contains(got, "%0A") || strings.Contains(got, "%0D") {
		t.Errorf("title should not contain CR/LF escapes, got %q", got)
	}
	if !strings.Contains(got, "line1 line2 line3") {
		t.Errorf("expected newlines collapsed to spaces, got %q", got)
	}
}

func TestFormatGithubAnnotation_Levels(t *testing.T) {
	cases := []struct {
		viewLevel string
		ghPrefix  string
	}{
		{levelError, "::error "},
		{levelWarning, "::warning "},
		{levelNote, "::notice "},
		{levelInfo, "::notice "},
	}
	for _, c := range cases {
		got := formatGithubAnnotation("package/npm/lodash", "package/npm/lodash",
			auditFinding{Level: c.viewLevel, RuleID: "R", Title: "t", Message: "m"}, "")
		if !strings.HasPrefix(got, c.ghPrefix) {
			t.Errorf("level %q: expected prefix %q, got %q", c.viewLevel, c.ghPrefix, got)
		}
	}
}

func TestFormatGithubAnnotation_FileAndLine(t *testing.T) {
	got := formatGithubAnnotation(
		"package/npm/lodash", "package/npm/lodash",
		auditFinding{Level: levelWarning, RuleID: "R", Title: "Stale", Message: "msg", File: "package.json", Line: 42},
		"",
	)
	if !strings.Contains(got, "file=package.json") {
		t.Errorf("expected file= segment: %s", got)
	}
	if !strings.Contains(got, "line=42") {
		t.Errorf("expected line= segment: %s", got)
	}
	if !strings.Contains(got, "title=[package/npm/lodash] Stale") {
		t.Errorf("expected bracketed title with package key: %s", got)
	}
}

func TestFormatGithubAnnotation_NoFileOmitsBothSegments(t *testing.T) {
	got := formatGithubAnnotation(
		"package/npm/lodash", "package/npm/lodash",
		auditFinding{Level: levelWarning, RuleID: "R", Title: "Stale", Message: "msg"},
		"",
	)
	if strings.Contains(got, "file=") {
		t.Errorf("expected no file= segment when File empty: %s", got)
	}
	if strings.Contains(got, "line=") {
		t.Errorf("expected no line= segment when File empty: %s", got)
	}
}

func TestFormatGithubAnnotation_FileOnlyNoLine(t *testing.T) {
	got := formatGithubAnnotation(
		"package/npm/lodash", "package/npm/lodash",
		auditFinding{Level: levelWarning, RuleID: "R", Title: "Stale", Message: "msg", File: "Gemfile"},
		"",
	)
	if !strings.Contains(got, "file=Gemfile") {
		t.Errorf("expected file= segment: %s", got)
	}
	if strings.Contains(got, "line=") {
		t.Errorf("expected no line= segment when Line is zero: %s", got)
	}
}

func TestFormatGithubAnnotation_LocalSourceDropsBracketedPrefix(t *testing.T) {
	got := formatGithubAnnotation(
		"local-source", "pypi/test",
		auditFinding{Level: levelError, RuleID: "R", Title: "Bad", Message: "msg"},
		"",
	)
	if strings.Contains(got, "[local-source]") {
		t.Errorf("local-source runID should not produce a bracketed prefix: %s", got)
	}
	if !strings.Contains(got, "title=Bad") {
		t.Errorf("expected plain title: %s", got)
	}
}

func TestFormatGithubAnnotation_TitleFallsBackToPkgKeyWhenNoRunID(t *testing.T) {
	got := formatGithubAnnotation(
		"", "package/npm/lodash",
		auditFinding{Level: levelWarning, RuleID: "R", Title: "Stale", Message: "msg"},
		"",
	)
	if !strings.Contains(got, "title=[package/npm/lodash] Stale") {
		t.Errorf("expected package key fallback in title: %s", got)
	}
}

func TestFormatGithubAnnotation_MessageEscaped(t *testing.T) {
	got := formatGithubAnnotation(
		"local-source", "local-source",
		auditFinding{Level: levelError, RuleID: "R", Title: "T", Message: "line1\nline2, with: colons"},
		"",
	)
	if !strings.Contains(got, "line1%0Aline2%2C with%3A colons") {
		t.Errorf("expected encoded message body: %s", got)
	}
}

func TestRelativizePath(t *testing.T) {
	cases := []struct {
		name, file, root, want string
	}{
		{"empty", "", "/repo", ""},
		{"already relative", "package.json", "/repo", "package.json"},
		{"abs under root", "/repo/src/package.json", "/repo", "src/package.json"},
		{"abs outside root", "/elsewhere/package.json", "/repo", ""},
		{"abs without root", "/repo/foo", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := relativizePath(c.file, c.root); got != c.want {
				t.Errorf("relativizePath(%q,%q): got %q want %q", c.file, c.root, got, c.want)
			}
		})
	}
}

func TestRenderGitHub_EndToEnd(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "package/npm/lodash", RuleID: "R1", Level: "error", Message: "boom", ShortDescription: "Boom title"},
		{Package: "package/npm/express", RuleID: "R2", Level: "warning", Message: "warn", ShortDescription: "Warn title"},
	})

	var out, errBuf bytes.Buffer
	if err := renderGitHub(&out, &errBuf, report, "all", nil, ""); err != nil {
		t.Fatalf("renderGitHub: %v", err)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 annotation lines, got %d:\n%s", len(lines), out.String())
	}
	// sorted by package key; express comes before lodash
	if !strings.HasPrefix(lines[0], "::warning ") || !strings.Contains(lines[0], "package/npm/express") {
		t.Errorf("line 0 unexpected: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "::error ") || !strings.Contains(lines[1], "package/npm/lodash") {
		t.Errorf("line 1 unexpected: %s", lines[1])
	}
}

func TestRenderGitHub_LevelFilter(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "p1", RuleID: "R1", Level: "error", Message: "e"},
		{Package: "p2", RuleID: "R2", Level: "warning", Message: "w"},
		{Package: "p3", RuleID: "R3", Level: "note", Message: "n"},
	})
	var out, errBuf bytes.Buffer
	if err := renderGitHub(&out, &errBuf, report, "error", nil, ""); err != nil {
		t.Fatalf("renderGitHub: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "::error ") {
		t.Errorf("expected single ::error line, got: %v", lines)
	}
}
