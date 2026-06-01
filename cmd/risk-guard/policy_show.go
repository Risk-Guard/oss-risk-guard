package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"github.com/fatih/color"
)

// renderEffectivePolicy produces a human-readable, colored view of the
// effective policy. Severity rules print first (the bulk of what an operator
// reasons about), then the workflow mode, then expected failures. It returns
// the full text so the caller can do a single checked write to stdout.
func renderEffectivePolicy(repoPath string, pol *policy.Policy, hasFile bool) string {
	var b strings.Builder
	bold := color.New(color.Bold).Sprint
	line := func(s string) { b.WriteString(s + "\n") }
	section := func(title string) { b.WriteString("\n" + bold(title) + "\n") }

	line(bold("Effective policy") + "  " + color.CyanString(repoPath))
	if hasFile {
		line(color.HiBlackString("built-in default + %s overrides", policy.PolicyFileName))
	} else {
		line(color.HiBlackString("no %s — built-in default only", policy.PolicyFileName))
	}

	// Severity rules first.
	section("Severity rules")
	if len(pol.Severity) == 0 {
		line("  " + color.HiBlackString("(none)"))
	} else {
		paths := make([]string, 0, len(pol.Severity))
		width := 0
		for p := range pol.Severity {
			paths = append(paths, p)
			if len(p) > width {
				width = len(p)
			}
		}
		sort.Strings(paths)
		for _, p := range paths {
			sv := pol.Severity[p]
			line(fmt.Sprintf("  %-*s  %s", width, p, colorSeverity(sv.Severity)))
			if sv.Reason != "" {
				line(fmt.Sprintf("  %-*s  %s", width, "", color.HiBlackString("↳ %s", sv.Reason)))
			}
			if sv.BlockingAfter != nil {
				line(fmt.Sprintf("  %-*s  %s", width, "",
					color.HiBlackString("↳ blocking after %s", sv.BlockingAfter.Format("2006-01-02"))))
			}
		}
	}

	// Workflow mode.
	section("Workflow")
	mode := policy.WorkflowModeActive
	if pol.Workflow != nil && pol.Workflow.Mode != "" {
		mode = pol.Workflow.Mode
	}
	line(fmt.Sprintf("  mode  %s  %s", colorMode(mode), color.HiBlackString("(%s)", modeBlurb(mode))))

	// Expected failures.
	section("Expected failures")
	if len(pol.ExpectedFailures) == 0 {
		line("  " + color.HiBlackString("(none)"))
	} else {
		entities := make([]string, 0, len(pol.ExpectedFailures))
		for e := range pol.ExpectedFailures {
			entities = append(entities, e)
		}
		sort.Strings(entities)
		for _, e := range entities {
			ef := pol.ExpectedFailures[e]
			line("  " + color.CyanString(e))
			line(fmt.Sprintf("    %s %s", color.HiBlackString("checks  "), strings.Join(ef.Checks, ", ")))
			if ef.Reason != "" {
				line(fmt.Sprintf("    %s %s", color.HiBlackString("reason  "), ef.Reason))
			}
			if ef.Expires != nil {
				line(fmt.Sprintf("    %s %s", color.HiBlackString("expires "), ef.Expires.Format("2006-01-02")))
			}
			if ef.ApprovedBy != "" {
				line(fmt.Sprintf("    %s %s", color.HiBlackString("by      "), ef.ApprovedBy))
			}
		}
	}

	return b.String()
}

// colorSeverity colors a severity level: blocking is red, warning yellow,
// ignore dimmed.
func colorSeverity(s policy.Severity) string {
	switch s {
	case policy.SeverityBlocking:
		return color.RedString(string(s))
	case policy.SeverityWarning:
		return color.YellowString(string(s))
	case policy.SeverityIgnore:
		return color.HiBlackString(string(s))
	default:
		return string(s)
	}
}

// colorMode colors the workflow mode: active (the only failing mode) green,
// the non-failing modes yellow.
func colorMode(m policy.WorkflowMode) string {
	if m == policy.WorkflowModeActive {
		return color.GreenString(string(m))
	}
	return color.YellowString(string(m))
}

func modeBlurb(m policy.WorkflowMode) string {
	switch m {
	case policy.WorkflowModeActive:
		return "fails the build on blocking findings"
	case policy.WorkflowModeNoFail:
		return "annotates but never fails"
	case policy.WorkflowModeSilent, policy.WorkflowModeDisabled:
		return "no annotations, never fails"
	default:
		return "unknown mode"
	}
}
