package main

import (
	"fmt"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
)

var (
	viewAuditGitHub   bool
	viewAuditGitLab   string
	viewAuditRepoRoot string
)

var viewAuditCmd = &cobra.Command{
	Use:   "view-audit <sarif-file>",
	Short: "Render the run's findings from a saved SARIF report",
	Long: `Read a SARIF 2.1.0 report produced by 'run'/'checks' or 'audit' and render it
exactly as the run that produced it would: the policy summary, the live findings
(blocking + warnings; acknowledged and ignored drop to the count), and the
pass/fail verdict. The only difference from 'run' is that the report is read from
disk instead of produced by a fresh scan — so view-audit replays a run's output,
and its exit code reflects the same policy.

With --github, emit GitHub Actions workflow annotations on stdout instead of the
text summary. With --gitlab <file>, also write a GitLab Code Quality (CodeClimate)
report to that file. The workflow mode (which gates output and whether blocking
findings fail) is read from .risk-guard.yml under --repo-root (default: the
current directory, or $GITHUB_WORKSPACE/$CI_PROJECT_DIR in CI).

Examples:
  risk-guard view-audit risk-guard-report.sarif
  risk-guard view-audit risk-guard-report.sarif --github
  risk-guard view-audit risk-guard-report.sarif --gitlab gl-code-quality-report.json`,
	Args: cobra.ExactArgs(1),
	RunE: runViewAudit,
}

func init() {
	viewAuditCmd.Flags().BoolVar(&viewAuditGitHub, "github", false, "Emit GitHub Actions workflow annotations on stdout instead of the text summary")
	viewAuditCmd.Flags().StringVar(&viewAuditGitLab, "gitlab", "", "Write a GitLab Code Quality (CodeClimate) report to this file (e.g. gl-code-quality-report.json)")
	viewAuditCmd.Flags().StringVar(&viewAuditRepoRoot, "repo-root", "", "Repo root: where .risk-guard.yml lives and what file paths are relative to (defaults to $GITHUB_WORKSPACE/$CI_PROJECT_DIR then CWD)")
	rootCmd.AddCommand(viewAuditCmd)
}

// runViewAudit reads a report off disk and hands it to the same renderReport the
// run uses, so a saved SARIF replays the run's summary, findings, and verdict.
func runViewAudit(_ *cobra.Command, args []string) error {
	report, err := sarif.Open(args[0])
	if err != nil {
		return fmt.Errorf("reading SARIF: %w", err)
	}
	root := resolveRepoRoot(viewAuditRepoRoot)
	mode, err := resolveWorkflowMode("", root)
	if err != nil {
		return err
	}
	return renderReport(report, mode, viewAuditGitHub, viewAuditGitLab, root, args[0])
}

// auditFinding is one finding extracted from a SARIF result: its level, rule,
// human title, full message, and physical provenance (file:line).
type auditFinding struct {
	Level   string // "error" | "warning" | "note" | "info"
	RuleID  string
	Title   string // rule short description, fallback to RuleID
	Message string // full multi-line rationale + evidence
	File    string // physical location URI, empty if absent
	Line    int    // physical location startLine, 0 if absent
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

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
