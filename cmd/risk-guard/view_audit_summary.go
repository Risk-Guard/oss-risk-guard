package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// writeGitHubStepSummary appends a markdown findings table to the file named by
// $GITHUB_STEP_SUMMARY. It is a no-op outside GitHub Actions (env var unset).
// The table is ordered errors-first — the convention for a top-down rollup —
// which is intentionally the reverse of the annotation stream's errors-last.
func writeGitHubStepSummary(report *sarif.Report, pkgFilter map[string]bool, levelFilter string) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}

	findings, _ := collectGHFindings(report, pkgFilter, levelFilter)
	sort.SliceStable(findings, func(i, j int) bool {
		if ri, rj := levelRank(findings[i].f.Level), levelRank(findings[j].f.Level); ri != rj {
			return ri < rj // errors first in the table
		}
		if findings[i].subject != findings[j].subject {
			return findings[i].subject < findings[j].subject
		}
		return findings[i].f.RuleID < findings[j].f.RuleID
	})

	var b strings.Builder
	b.WriteString("## Risk Guard\n\n")
	if len(findings) == 0 {
		b.WriteString("✅ No findings.\n")
		return appendFile(path, b.String())
	}

	b.WriteString(summaryHeadline(findings))
	b.WriteString("\n\n")
	b.WriteString("| Severity | Subject | Finding | Rule | Location |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, gf := range findings {
		rationale, _, _ := splitMessageParts(gf.f.Message)
		rationale = stripSubjectPrefix(rationale, gf.pkg)
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			severityCell(gf.f.Level),
			mdCell(gf.subject),
			mdCell(rationale),
			mdCell(gf.f.RuleID),
			mdCell(locationCell(gf.f)))
	}

	return appendFile(path, b.String())
}

func summaryHeadline(findings []ghFinding) string {
	var c levelCounts
	for _, gf := range findings {
		switch gf.f.Level {
		case levelError:
			c.Error++
		case levelWarning:
			c.Warning++
		case levelNote:
			c.Note++
		case levelInfo:
			c.Info++
		}
	}
	var parts []string
	if c.Error > 0 {
		parts = append(parts, fmt.Sprintf("❌ %d blocking", c.Error))
	}
	if c.Warning > 0 {
		parts = append(parts, fmt.Sprintf("⚠️ %d warning", c.Warning))
	}
	if c.Note > 0 {
		parts = append(parts, fmt.Sprintf("🔵 %d acknowledged", c.Note))
	}
	if c.Info > 0 {
		parts = append(parts, fmt.Sprintf("⬜ %d ignored", c.Info))
	}
	if len(parts) == 0 {
		return "✅ No findings."
	}
	return "**" + strings.Join(parts, " · ") + "**"
}

func severityCell(level string) string {
	switch level {
	case levelError:
		return "❌ error"
	case levelWarning:
		return "⚠️ warning"
	case levelNote:
		return "🔵 note"
	default:
		return "⬜ info"
	}
}

func locationCell(f auditFinding) string {
	if f.File == "" {
		return "—"
	}
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

// mdCell makes a string safe for a single markdown table cell: pipes escaped,
// newlines flattened to spaces.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	return s
}

// appendFile appends content to path, creating it if absent. path comes from
// the trusted $GITHUB_STEP_SUMMARY env var that the Actions runner controls.
func appendFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec // path is the runner-provided $GITHUB_STEP_SUMMARY
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		return err
	}
	return nil
}
