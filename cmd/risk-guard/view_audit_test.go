package main

import (
	"bytes"
	"os"
	"slices"
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

func TestBlockingFindingLines(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "package/pypi/beautifulsoup4", RuleID: "SOURCE_REPO_NOT_FOUND", Level: "error", Message: "repo not found", ShortDescription: "Source repository could not be found or accessed"},
		{Package: "package/npm/lodash", RuleID: "WARN_RULE", Level: "warning", Message: "just a warning", ShortDescription: "A warning"},
		{Package: "package/pypi/numpy", RuleID: "PACKAGE_INSTALL_SCRIPTS", Level: "error", Message: "install scripts", ShortDescription: "Package runs install scripts"},
	})

	lines := blockingFindingLines(report)

	// Exactly the error-level results — the list length must equal the verdict tally.
	if got := countErrorLevel(report); got != len(lines) {
		t.Fatalf("blocking lines (%d) must equal countErrorLevel (%d): %v", len(lines), got, lines)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 blocking lines, got %d: %v", len(lines), lines)
	}

	joined := strings.Join(lines, "\n")
	// Each line names the subject, the human title, and the check code.
	if !strings.Contains(joined, "beautifulsoup4 (pypi)") ||
		!strings.Contains(joined, "Source repository could not be found or accessed") ||
		!strings.Contains(joined, "SOURCE_REPO_NOT_FOUND") {
		t.Errorf("missing bs4 blocking detail:\n%s", joined)
	}
	if !strings.Contains(joined, "numpy (pypi)") || !strings.Contains(joined, "PACKAGE_INSTALL_SCRIPTS") {
		t.Errorf("missing numpy blocking detail:\n%s", joined)
	}
	// Warnings must never appear in the blocking list.
	if strings.Contains(joined, "WARN_RULE") || strings.Contains(joined, "lodash") {
		t.Errorf("warning leaked into blocking lines:\n%s", joined)
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

func TestGithubEscapeData(t *testing.T) {
	in := "line1\nline2\rwith, comma: colon 50% off"
	got := githubEscapeData(in)
	// Message body: only %, CR, LF are encoded. `,` and `:` pass through —
	// GitHub does not decode %2C/%3A there, so encoding them would render as
	// literal `%2C`/`%3A` in the annotation card.
	want := "line1%0Aline2%0Dwith, comma: colon 50%25 off"
	if got != want {
		t.Errorf("escape mismatch:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestGithubEscapeProperty(t *testing.T) {
	in := "line1\nline2\rwith, comma: colon 50% off"
	got := githubEscapeProperty(in)
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

func TestSplitMessageParts(t *testing.T) {
	rationale, evidence, note := splitMessageParts(
		"headline\n\nEvidence:\n- one\n- two\n\nNote: heads up")
	if rationale != "headline" {
		t.Errorf("rationale = %q", rationale)
	}
	if len(evidence) != 2 || evidence[0] != "one" || evidence[1] != "two" {
		t.Errorf("evidence = %#v", evidence)
	}
	if note != "heads up" {
		t.Errorf("note = %q", note)
	}

	// No evidence/note blocks: the whole message is the rationale.
	r2, e2, n2 := splitMessageParts("just a headline")
	if r2 != "just a headline" || e2 != nil || n2 != "" {
		t.Errorf("plain message parsed wrong: %q %#v %q", r2, e2, n2)
	}
}

func TestStripSubjectPrefix(t *testing.T) {
	cases := []struct{ name, line, pkg, want string }{
		{"strips eco/name", "rubygems/example: no license", "package/rubygems/example", "no license"},
		{"strips eco/name@version", "npm/lodash@4.0.0: stale", "package/npm/lodash?version=4.0.0", "stale"},
		{"leaves unrelated prefix", "Source Code: https://x", "package/npm/lodash", "Source Code: https://x"},
		{"non-package key untouched", "source/x: y", "source/github.com/o/r", "source/x: y"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stripSubjectPrefix(c.line, c.pkg); got != c.want {
				t.Errorf("stripSubjectPrefix(%q,%q) = %q, want %q", c.line, c.pkg, got, c.want)
			}
		})
	}
}

func TestDedupeEvidence(t *testing.T) {
	cases := []struct {
		name           string
		ev             []string
		rationale, pkg string
		want           []string
	}{
		{
			name:      "drops item restating the headline",
			ev:        []string{"rubygems/example: Package does not declare a license"},
			rationale: "Package does not declare a license",
			pkg:       "package/rubygems/example",
			want:      nil,
		},
		{
			name:      "keeps distinct detail",
			ev:        []string{"Source Code: https://x"},
			rationale: "no license",
			pkg:       "package/npm/x",
			want:      []string{"Source Code: https://x"},
		},
		{
			name:      "collapses exact duplicates",
			ev:        []string{"same", "same"},
			rationale: "headline",
			pkg:       "package/npm/x",
			want:      []string{"same"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dedupeEvidence(c.ev, c.rationale, c.pkg); !slices.Equal(got, c.want) {
				t.Errorf("dedupeEvidence = %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestAnnotationSubject(t *testing.T) {
	cases := []struct{ name, runID, pkg, want string }{
		{"local-source runID", "local-source", "source/github.com/o/r", "your repository"},
		{"source key prefix", "", "source/github.com/o/r", "your repository"},
		{"package humanized", "", "package/npm/lodash?version=4.0.0", "lodash@4.0.0 (npm)"},
		{"package no version", "", "package/rubygems/example", "example (rubygems)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := annotationSubject(c.runID, c.pkg); got != c.want {
				t.Errorf("annotationSubject(%q,%q) = %q, want %q", c.runID, c.pkg, got, c.want)
			}
		})
	}
}

// File/line segments are emitted only when present — the behavioral contract for
// PR-diff placement, independent of message wording.
func TestFormatGithubAnnotation_FileSegments(t *testing.T) {
	mk := func(file string, line int) string {
		return formatGithubAnnotation("package/npm/lodash", "package/npm/lodash",
			auditFinding{Level: levelWarning, RuleID: "R", Title: "Stale", Message: "msg", File: file, Line: line}, "")
	}
	if got := mk("package.json", 42); !strings.Contains(got, "file=package.json") || !strings.Contains(got, "line=42") {
		t.Errorf("file+line: expected both segments: %s", got)
	}
	if got := mk("Gemfile", 0); !strings.Contains(got, "file=Gemfile") || strings.Contains(got, "line=") {
		t.Errorf("file-only: expected file= without line=: %s", got)
	}
	if got := mk("", 0); strings.Contains(got, "file=") || strings.Contains(got, "line=") {
		t.Errorf("no-file: expected neither segment: %s", got)
	}
}

// Regression (live PR #6, where users saw `%3A`/`%2C` in the annotation card):
// the message body must use escapeData so `:`/`,` stay literal and GitHub
// renders them correctly, while the title is a property value and must encode
// them. Asserts the escaping contract, not a wording snapshot.
func TestFormatGithubAnnotation_BodyKeepsPunctuationLiteral(t *testing.T) {
	got := formatGithubAnnotation(
		"package/pypi/f-ask", "package/pypi/f-ask",
		auditFinding{
			Level:   levelError,
			RuleID:  "R",
			Title:   "Name: mismatch, see source",
			Message: "found at https://github.com/pallets/flask",
		},
		"",
	)
	parts := strings.SplitN(got, "::", 3)
	if len(parts) != 3 {
		t.Fatalf("expected `::level props::message` framing, got: %s", got)
	}
	props, message := parts[1], parts[2]
	if strings.Contains(message, "%3A") || strings.Contains(message, "%2C") {
		t.Errorf("message body must keep `:`/`,` literal: %s", message)
	}
	if !strings.Contains(message, "https://github.com/pallets/flask") {
		t.Errorf("expected literal URL in body: %s", message)
	}
	// The title contains a `:` and `,`, which must be encoded as a property value.
	if !strings.Contains(props, "%3A") || !strings.Contains(props, "%2C") {
		t.Errorf("title property must encode `:`/`,`: %s", props)
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

// Findings are emitted least-to-most severe so blocking findings land last.
func TestRenderGitHub_ErrorsLast(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "package/npm/a", RuleID: "R1", Level: "error", Message: "boom"},
		{Package: "package/npm/b", RuleID: "R2", Level: "warning", Message: "warn"},
		{Package: "package/npm/c", RuleID: "R3", Level: "note", Message: "ack"},
	})
	var out, errBuf bytes.Buffer
	if err := renderGitHub(&out, &errBuf, report, "all", nil, ""); err != nil {
		t.Fatalf("renderGitHub: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %s", len(lines), out.String())
	}
	if !strings.HasPrefix(lines[0], "::notice ") ||
		!strings.HasPrefix(lines[1], "::warning ") ||
		!strings.HasPrefix(lines[2], "::error ") {
		t.Errorf("expected notice, warning, error order; got:\n%s", out.String())
	}
}

func TestWriteGitHubStepSummary(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "package/npm/lodash", RuleID: "STALE", Level: "error", Message: "lodash: stale release", ShortDescription: "Stale"},
		{Package: "package/npm/express", RuleID: "NO_LICENSE", Level: "warning", Message: "no license"},
	})
	path := t.TempDir() + "/summary.md"
	t.Setenv("GITHUB_STEP_SUMMARY", path)

	if err := writeGitHubStepSummary(report, nil, "all"); err != nil {
		t.Fatalf("writeGitHubStepSummary: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading summary: %v", err)
	}
	got := string(data)

	// Counts reflect the findings.
	if !strings.Contains(got, "1 blocking") || !strings.Contains(got, "1 warning") {
		t.Errorf("expected blocking + warning counts:\n%s", got)
	}
	// Both subjects appear, with the error sorted before the warning
	// (the table is errors-first, the reverse of the annotation stream).
	li, ei := strings.Index(got, "lodash (npm)"), strings.Index(got, "express (npm)")
	if li < 0 || ei < 0 {
		t.Fatalf("expected both subjects in summary:\n%s", got)
	}
	if li > ei {
		t.Errorf("expected error row (lodash) before warning row (express):\n%s", got)
	}
}

func TestWriteGitHubStepSummary_NoEnvIsNoop(t *testing.T) {
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	report := newTestReport(t, []testFinding{{Package: "package/npm/x", RuleID: "R", Level: "error", Message: "m"}})
	if err := writeGitHubStepSummary(report, nil, "all"); err != nil {
		t.Errorf("expected no-op without env var, got: %v", err)
	}
}
