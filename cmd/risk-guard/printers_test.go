package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestLiveFindings_ExcludesAcknowledgedAndIgnored(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "package/pypi/foo", RuleID: "SOURCE_REPO_NOT_FOUND", Level: "error", Message: "no repo", ShortDescription: "Source repo not found"},
		{Package: "package/pypi/bar", RuleID: "PACKAGE_UNRELEASED_CHANGES", Level: "warning", Message: "ahead", ShortDescription: "Unreleased changes"},
		{Package: "package/pypi/baz", RuleID: "ACK_RULE", Level: "note", Message: "ack", ShortDescription: "Acknowledged"},
		{Package: "package/pypi/qux", RuleID: "IGN_RULE", Level: "none", Message: "ign", ShortDescription: "Ignored"},
	})

	live := selectFindingsByLevel(report, isLiveLevel)
	if len(live) != 2 {
		t.Fatalf("expected 2 live findings (error+warning), got %d: %+v", len(live), live)
	}
	codes := map[string]bool{}
	for _, f := range live {
		codes[f.f.RuleID] = true
	}
	if !codes["SOURCE_REPO_NOT_FOUND"] || !codes["PACKAGE_UNRELEASED_CHANGES"] {
		t.Errorf("missing live findings: %v", codes)
	}
	if codes["ACK_RULE"] || codes["IGN_RULE"] {
		t.Errorf("acknowledged/ignored leaked into live findings: %v", codes)
	}
}

func TestTextPrinter_RendersLiveGroupedBySubject(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "package/pypi/foo", RuleID: "SOURCE_REPO_NOT_FOUND", Level: "error", Message: "could not resolve", ShortDescription: "Source repo not found", File: "requirements.txt", Line: 7},
		{Package: "package/pypi/foo", RuleID: "PACKAGE_INSTALL_SCRIPTS", Level: "warning", Message: "install scripts", ShortDescription: "Install scripts"},
		{Package: "package/pypi/acked", RuleID: "ACK_RULE", Level: "note", Message: "ack", ShortDescription: "Acked"},
	})

	var buf bytes.Buffer
	if err := renderFindings(selectFindingsByLevel(report, isLiveLevel), []Printer{newTextPrinter(&buf)}); err != nil {
		t.Fatalf("renderFindings: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "foo (pypi)") || !strings.Contains(out, "SOURCE_REPO_NOT_FOUND") || !strings.Contains(out, "requirements.txt:7") {
		t.Errorf("missing live finding detail:\n%s", out)
	}
	if !strings.Contains(out, "ERROR") || !strings.Contains(out, "WARNING") {
		t.Errorf("expected ERROR and WARNING levels printed:\n%s", out)
	}
	// The acknowledged finding must not appear in the live output.
	if strings.Contains(out, "ACK_RULE") || strings.Contains(out, "acked") {
		t.Errorf("acknowledged finding leaked into text output:\n%s", out)
	}
}
