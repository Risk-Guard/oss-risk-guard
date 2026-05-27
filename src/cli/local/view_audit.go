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
)

var viewAuditCmd = &cobra.Command{
	Use:   "view-audit <sarif-file>",
	Short: "Render a human-readable summary of an audit SARIF file",
	Long: `Read a SARIF 2.1.0 report produced by 'audit' or 'audit-package' and
print a per-package summary of findings.

Examples:
  risk-guard-local view-audit audit.sarif
  risk-guard-local view-audit audit.sarif --level error
  risk-guard-local view-audit audit.sarif --package lodash --package express`,
	Args: cobra.ExactArgs(1),
	RunE: runViewAudit,
}

func init() {
	viewAuditCmd.Flags().StringVar(&viewAuditLevel, "level", "all", "Filter findings by level: error, warning, note, info, all")
	viewAuditCmd.Flags().StringArrayVar(&viewAuditPackages, "package", nil, "Filter to specific package names (repeatable)")
	rootCmd.AddCommand(viewAuditCmd)
}

func runViewAudit(_ *cobra.Command, args []string) error {
	report, err := sarif.Open(args[0])
	if err != nil {
		return fmt.Errorf("reading SARIF: %w", err)
	}
	return renderAudit(os.Stdout, report, viewAuditLevel, viewAuditPackages)
}

type auditFinding struct {
	Level   string // "error" | "warning" | "note" | "info"
	RuleID  string
	Title   string // rule short description, fallback to RuleID
	Message string // full multi-line rationale + evidence
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
			grouped[pkg] = append(grouped[pkg], auditFinding{
				Level:   lvl,
				RuleID:  ruleID,
				Title:   title,
				Message: strings.TrimSpace(derefString(res.Message.Text)),
			})
		}
	}
	return grouped, skipped
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
		for line := range strings.SplitSeq(f.Message, "\n") {
			if _, err := fmt.Fprintf(w, "           %s\n", line); err != nil {
				return err
			}
		}
	}
	return nil
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
