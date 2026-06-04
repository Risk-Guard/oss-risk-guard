package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
)

const sourceRepoNotFoundCode = "SOURCE_REPO_NOT_FOUND"

// sourceURLFinding is a SOURCE_REPO_NOT_FOUND finding projected for the URL
// prompt: the package it belongs to and the current URL (empty when the package
// defines no source at all).
type sourceURLFinding struct {
	EntityKey string
	Current   string
}

// triageSourceURLs offers to correct the source URL for every package whose
// repository could not be located (SOURCE_REPO_NOT_FOUND). Entered URLs are
// written to pol.Overrides and the affected packages are re-audited against the
// corrected source — only they re-score, the rest are served from cache — so the
// returned report (and the baseline triaged from it) reflect the fix. Packages
// left blank stay as findings the caller can acknowledge.
func triageSourceURLs(cmd *cobra.Command, repoPath string, report *sarif.Report, outPath string, pol *policy.Policy) (*sarif.Report, error) {
	findings := collectSourceURLFindings(report)
	if len(findings) == 0 {
		return report, nil
	}

	overrides, err := promptSourceURLOverrides(findings)
	if err != nil {
		return nil, err
	}
	if len(overrides) == 0 {
		return report, nil
	}

	pol.Overrides = overrides
	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "\nRe-auditing %d package(s) with corrected source URLs (others served from cache)…\n", len(overrides))

	updated, err := runInitPipeline(cmd, repoPath, overrides)
	if err != nil {
		return nil, err
	}
	if err := writeReport(updated, outPath); err != nil {
		return nil, err
	}
	return updated, nil
}

// collectSourceURLFindings extracts one entry per package that hit
// SOURCE_REPO_NOT_FOUND. The local source ("root") is excluded — its URL is the
// scanned path and not overridable.
func collectSourceURLFindings(report *sarif.Report) []sourceURLFinding {
	var out []sourceURLFinding
	seen := map[string]bool{}
	for _, run := range report.Runs {
		for _, res := range run.Results {
			if derefString(res.RuleID) != sourceRepoNotFoundCode {
				continue
			}
			key := entityKeyForResult(res)
			if key == "root" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, sourceURLFinding{
				EntityKey: key,
				Current:   currentURLFromMessage(derefString(res.Message.Text)),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EntityKey < out[j].EntityKey })
	return out
}

// currentURLFromMessage pulls the "URL: <url>" evidence line out of a
// SOURCE_REPO_NOT_FOUND message. Returns "" when the package defined no URL.
func currentURLFromMessage(msg string) string {
	for line := range strings.SplitSeq(msg, "\n") {
		line = strings.TrimPrefix(strings.TrimSpace(line), "- ")
		if u, ok := strings.CutPrefix(line, "URL: "); ok {
			return strings.TrimSpace(u)
		}
	}
	return ""
}

// promptSourceURLOverrides asks the user for a corrected repository URL per
// finding and returns the overrides to record. Blank input skips that package.
func promptSourceURLOverrides(findings []sourceURLFinding) (map[string][]policy.PolicyOverride, error) {
	printSourceURLIntro(len(findings))

	overrides := map[string][]policy.PolicyOverride{}
	for _, f := range findings {
		title := fmt.Sprintf("%s — no source repository defined", humanPackageName(f.EntityKey))
		if f.Current != "" {
			title = fmt.Sprintf("%s — source repo not found at %s", humanPackageName(f.EntityKey), f.Current)
		}

		var url string
		if err := huh.NewInput().
			Title(title).
			Description("Enter the correct git repository URL (leave blank to skip):").
			Value(&url).
			Run(); err != nil {
			return nil, err
		}

		url = strings.TrimSpace(url)
		if url == "" {
			continue // left blank: no change, nothing to echo
		}
		echoChoice("%s → %s", humanPackageName(f.EntityKey), url)
		overrides[f.EntityKey] = []policy.PolicyOverride{{
			Path:   "output.source_url",
			Value:  url,
			Reason: "Corrected source URL provided during risk-guard init",
		}}
	}
	if len(overrides) == 0 {
		echoGroupDone("No source URLs corrected")
	} else {
		echoGroupDone("Corrected %d source URL(s)", len(overrides))
	}
	return overrides, nil
}

// printSourceURLIntro explains the source-URL prompt before it runs.
func printSourceURLIntro(n int) {
	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "\nFound %d package(s) whose source repository could not be located.\n", n)
	fmt.Fprintln(os.Stderr, "Their source can't be verified, and source checks (license, CI, contributors…)")
	fmt.Fprintln(os.Stderr, "can't run. If you know the real repository URL, enter it and Risk Guard will")
	fmt.Fprintln(os.Stderr, "re-audit the package against the correct source (recorded under overrides).")
	fmt.Fprintln(os.Stderr, "Leave blank to skip — it stays a finding you can acknowledge below.")
	fmt.Fprintln(os.Stderr)
}
