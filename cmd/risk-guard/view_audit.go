package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
)

var (
	viewAuditLevel    string
	viewAuditPackages []string
	viewAuditGitHub   bool
	viewAuditGitLab   string
	viewAuditRepoRoot string
)

var viewAuditCmd = &cobra.Command{
	Use:   "view-audit <sarif-file>",
	Short: "Render a human-readable summary of an audit SARIF file",
	Long: `Read a SARIF 2.1.0 report produced by 'audit' or 'audit-package' and
print a per-package summary of findings.

With --github, emit GitHub Actions workflow annotations instead of the text
summary, one line per finding. When the SARIF carries physicalLocation, the
annotation points at the manifest file + line (relative to --repo-root or
$GITHUB_WORKSPACE, defaulting to the current directory).

With --gitlab <file>, also write a GitLab Code Quality (CodeClimate) report to
that file. GitLab renders it inline on the merge request diff; it composes with
the stdout summary or --github.

Examples:
  risk-guard view-audit audit.sarif
  risk-guard view-audit audit.sarif --level error
  risk-guard view-audit audit.sarif --package lodash --package express
  risk-guard view-audit audit.sarif --github
  risk-guard view-audit audit.sarif --gitlab gl-code-quality-report.json`,
	Args: cobra.ExactArgs(1),
	RunE: runViewAudit,
}

func init() {
	viewAuditCmd.Flags().StringVar(&viewAuditLevel, "level", "all", "Filter findings by level: error, warning, note, info, all")
	viewAuditCmd.Flags().StringArrayVar(&viewAuditPackages, "package", nil, "Filter to specific package names (repeatable)")
	viewAuditCmd.Flags().BoolVar(&viewAuditGitHub, "github", false, "Emit GitHub Actions workflow annotations instead of human-readable summary")
	viewAuditCmd.Flags().StringVar(&viewAuditGitLab, "gitlab", "", "Write a GitLab Code Quality (CodeClimate) report to this file (e.g. gl-code-quality-report.json)")
	viewAuditCmd.Flags().StringVar(&viewAuditRepoRoot, "repo-root", "", "Root to make file paths relative to (defaults to $GITHUB_WORKSPACE/$CI_PROJECT_DIR then CWD); used with --github/--gitlab")
	rootCmd.AddCommand(viewAuditCmd)
}

func runViewAudit(_ *cobra.Command, args []string) error {
	report, err := sarif.Open(args[0])
	if err != nil {
		return fmt.Errorf("reading SARIF: %w", err)
	}
	mode := DisplayText
	if viewAuditGitHub {
		mode = DisplayGitHub
	}
	if err := renderReport(os.Stdout, os.Stderr, report, mode, viewAuditLevel, viewAuditPackages, viewAuditRepoRoot); err != nil {
		return err
	}
	// --gitlab writes a report file and composes with the stdout summary/--github.
	if viewAuditGitLab != "" {
		return writeGitLabReport(viewAuditGitLab, report, viewAuditLevel, viewAuditPackages, viewAuditRepoRoot)
	}
	return nil
}

// DisplayMode selects how an in-memory SARIF report is rendered to the user
// after a command finishes. DisplayNone is the historical default (write
// SARIF only). DisplayText is the per-package human summary. DisplayGitHub
// emits one GH Actions workflow command per finding.
type DisplayMode int

const (
	DisplayNone DisplayMode = iota
	DisplayText
	DisplayGitHub
)

// renderReport dispatches an in-memory report to the requested renderer.
// Reuses renderAudit and renderGitHub verbatim. level and packages are the
// existing view-audit filters; repoRoot is only used by DisplayGitHub.
// DisplayNone is a no-op so callers can call this unconditionally.
func renderReport(out io.Writer, warn io.Writer, report *sarif.Report, mode DisplayMode, level string, packages []string, repoRoot string) error {
	switch mode {
	case DisplayNone:
		return nil
	case DisplayText:
		return renderAudit(out, report, level, packages)
	case DisplayGitHub:
		return renderGitHub(out, warn, report, level, packages, repoRoot)
	default:
		return fmt.Errorf("unknown display mode: %d", mode)
	}
}

type auditFinding struct {
	Level   string // "error" | "warning" | "note" | "info"
	RuleID  string
	Title   string // rule short description, fallback to RuleID
	Message string // full multi-line rationale + evidence
	File    string // physical location URI, empty if absent
	Line    int    // physical location startLine, 0 if absent
}

func renderAudit(w io.Writer, report *sarif.Report, level string, packages []string) error {
	pkgFilter := stringSet(packages)
	levelFilter, err := normalizeLevelFilter(level)
	if err != nil {
		return err
	}

	grouped, skipped := collectFindings(report, pkgFilter, levelFilter)
	clean := cleanRunIDs(report, pkgFilter, grouped)

	for _, rule := range skipped {
		if _, err := fmt.Fprintf(w, "warning: skipping result with no package logical-location (rule=%s)\n", rule); err != nil {
			return err
		}
	}

	if len(grouped) == 0 && len(clean) == 0 {
		_, err := fmt.Fprintln(w, "no findings")
		return err
	}

	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)
	sort.Strings(clean)

	for i, name := range names {
		findings := grouped[name]
		sort.SliceStable(findings, func(i, j int) bool {
			if findings[i].Level != findings[j].Level {
				return levelRank(findings[i].Level) < levelRank(findings[j].Level)
			}
			return findings[i].RuleID < findings[j].RuleID
		})
		if err := renderPackage(w, name, findings); err != nil {
			return err
		}
		if i < len(names)-1 || len(clean) > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
	}
	for i, id := range clean {
		if _, err := fmt.Fprintf(w, "%s — no findings\n", humanPackageName(id)); err != nil {
			return err
		}
		if i < len(clean)-1 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
	}
	return nil
}

// cleanRunIDs returns the AutomationDetails.ID of every Run that produced no
// findings in grouped — i.e. packages that were audited and passed cleanly.
// Runs without an ID (older SARIF, local-source) are skipped.
func cleanRunIDs(report *sarif.Report, pkgFilter map[string]bool, grouped map[string][]auditFinding) []string {
	var out []string
	for _, run := range report.Runs {
		if run.AutomationDetails == nil || run.AutomationDetails.ID == nil {
			continue
		}
		id := *run.AutomationDetails.ID
		if id == "" || id == "local-source" {
			continue
		}
		if len(pkgFilter) > 0 && !pkgFilter[id] {
			continue
		}
		if _, hasFindings := grouped[id]; hasFindings {
			continue
		}
		out = append(out, id)
	}
	return out
}

func collectFindings(report *sarif.Report, pkgFilter map[string]bool, levelFilter string) (map[string][]auditFinding, []string) {
	grouped := map[string][]auditFinding{}
	var skipped []string
	for _, run := range report.Runs {
		titles := ruleTitleIndex(run)
		for _, res := range run.Results {
			pkg := packageFromResult(res)
			if pkg == "" {
				skipped = append(skipped, derefString(res.RuleID))
				continue
			}
			if len(pkgFilter) > 0 && !pkgFilter[pkg] {
				continue
			}
			lvl := normalizeLevel(derefString(res.Level))
			if levelFilter != "all" && lvl != levelFilter {
				continue
			}
			ruleID := derefString(res.RuleID)
			title := titles[ruleID]
			if title == "" {
				title = ruleID
			}
			file, line := physicalFromResult(res)
			grouped[pkg] = append(grouped[pkg], auditFinding{
				Level:   lvl,
				RuleID:  ruleID,
				Title:   title,
				Message: strings.TrimSpace(derefString(res.Message.Text)),
				File:    file,
				Line:    line,
			})
		}
	}
	return grouped, skipped
}

// physicalFromResult extracts the first location's physicalLocation file URI
// and startLine from a SARIF result. Returns ("", 0) if absent.
func physicalFromResult(res *sarif.Result) (string, int) {
	for _, loc := range res.Locations {
		if loc == nil || loc.PhysicalLocation == nil {
			continue
		}
		phys := loc.PhysicalLocation
		var file string
		if phys.ArtifactLocation != nil && phys.ArtifactLocation.URI != nil {
			file = *phys.ArtifactLocation.URI
		}
		var line int
		if phys.Region != nil && phys.Region.StartLine != nil {
			line = *phys.Region.StartLine
		}
		if file != "" || line > 0 {
			return file, line
		}
	}
	return "", 0
}

func ruleTitleIndex(run *sarif.Run) map[string]string {
	out := map[string]string{}
	if run == nil || run.Tool.Driver == nil {
		return out
	}
	for _, r := range run.Tool.Driver.Rules {
		if r == nil || r.ShortDescription == nil || r.ShortDescription.Text == nil {
			continue
		}
		out[r.ID] = *r.ShortDescription.Text
	}
	return out
}

func renderPackage(w io.Writer, displayName string, findings []auditFinding) error {
	counts := countByLevel(findings)
	header := fmt.Sprintf("%s — %d findings%s", humanPackageName(displayName), len(findings), formatCounts(counts))
	if _, err := fmt.Fprintln(w, header); err != nil {
		return err
	}
	for _, f := range findings {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %-7s  %s\n", strings.ToUpper(f.Level), f.Title); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "           %s\n", f.RuleID); err != nil {
			return err
		}
		// Where the finding was discovered (the manifest that declared a
		// dependency, or the source file) — the provenance that makes a finding
		// actionable. Skip the synthetic repo-root anchor (commonsarif
		// RepoRootURI = ".") that EnsurePhysicalLocations stamps on findings with
		// no real location; it isn't useful provenance.
		if f.File != "" && f.File != "." {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			if _, err := fmt.Fprintf(w, "           ↳ %s\n", loc); err != nil {
				return err
			}
		}
		for line := range strings.SplitSeq(f.Message, "\n") {
			if _, err := fmt.Fprintf(w, "           %s\n", line); err != nil {
				return err
			}
		}
	}
	return nil
}

// blockingFindingLines names every error-level result as
// "<subject> — <title> (<CHECK>)" so a failing run says exactly what blocks it.
// The predicate matches countErrorLevel, so the list length equals the
// "blocks N finding(s)" tally in the verdict.
func blockingFindingLines(report *sarif.Report) []string {
	if report == nil {
		return nil
	}
	runIDs := runIDByPkg(report)
	var lines []string
	for _, run := range report.Runs {
		titles := ruleTitleIndex(run)
		for _, res := range run.Results {
			if res.Level == nil || *res.Level != levelError {
				continue
			}
			rule := derefString(res.RuleID)
			pkg := packageFromResult(res)
			subject := annotationSubject(runIDs[pkg], pkg)
			if subject == "" {
				subject = "this repository"
			}
			title := titles[rule]
			if title == "" {
				title = rule
			}
			line := fmt.Sprintf("%s — %s (%s)", subject, title, rule)
			if file, ln := physicalFromResult(res); file != "" && file != "." {
				if ln > 0 {
					line += fmt.Sprintf("  from %s:%d", file, ln)
				} else {
					line += fmt.Sprintf("  from %s", file)
				}
			}
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return lines
}

// humanPackageName turns "package/npm/left-pad" into "left-pad (npm)" and
// "package/npm/lodash?version=4.17.20" into "lodash@4.17.20 (npm)". Any key
// parseKeyIdentity can't decode is returned unchanged.
func humanPackageName(key string) string {
	eco, name, version := parseKeyIdentity(key)
	if eco == "" || name == "" {
		return key
	}
	if version != "" {
		return name + "@" + version + " (" + eco + ")"
	}
	return name + " (" + eco + ")"
}

func packageFromResult(res *sarif.Result) string {
	for _, loc := range res.Locations {
		for _, ll := range loc.LogicalLocations {
			if ll.Kind != nil && *ll.Kind == "package" && ll.Name != nil {
				return *ll.Name
			}
			if ll.Name != nil && *ll.Name != "" {
				return *ll.Name
			}
		}
	}
	return ""
}

func stringSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		out[s] = true
	}
	return out
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// renderGitHub and its helpers live in view_audit_github.go to keep this file
// focused on the text rendering path.
