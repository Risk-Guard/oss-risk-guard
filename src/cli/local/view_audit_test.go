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
