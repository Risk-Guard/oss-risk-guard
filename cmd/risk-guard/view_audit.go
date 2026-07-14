package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
)

var (
	viewAuditGitHub   bool
	viewAuditGitLab   string
	viewAuditRepoRoot string
	viewAuditPackages []string
)

var viewAuditCmd = &cobra.Command{
	Use:   "view <sarif-file>",
	Short: "Render the run's findings from a saved SARIF report",
	Long: `Read a SARIF 2.1.0 report produced by 'run'/'checks' or 'audit deps' and render
it exactly as the run that produced it would: the policy summary, the live
findings (blocking + warnings by default), and the pass/fail verdict. The only
difference from 'run' is that the report is read from disk instead of produced by
a fresh scan — so 'audit view' replays a run's output, and its exit code reflects
the same policy.

Use --level to lower the display threshold and surface the suppressed findings
the summary otherwise only counts: --level acknowledged also shows acknowledged
findings, and --level all shows ignored ones too.

Use --package to show only the findings for one or more packages. A spec matches
by any of a package's identifying forms, so both the bare name and the full
logical location select it — --package embla-carousel-react,
--package package/npm/embla-carousel-react, --package npm/embla-carousel-react,
and --package embla-carousel-react@8.6.0 all pick the same package. Repeat the
flag to keep several packages. The policy summary and pass/fail verdict still
reflect the whole report; only the displayed findings are narrowed.

With --github, emit GitHub Actions workflow annotations on stdout instead of the
text summary. With --gitlab <file>, also write a GitLab Code Quality (CodeClimate)
report to that file. The workflow mode (which gates output and whether blocking
findings fail) is read from .risk-guard.yml under --repo-root (default: the
current directory, or $GITHUB_WORKSPACE/$CI_PROJECT_DIR in CI).

Examples:
  risk-guard audit view risk-guard-report.sarif
  risk-guard audit view risk-guard-report.sarif --github
  risk-guard audit view risk-guard-report.sarif --gitlab gl-code-quality-report.json`,
	Args: cobra.ExactArgs(1),
	RunE: runViewAudit,
}

func init() {
	viewAuditCmd.Flags().BoolVar(&viewAuditGitHub, "github", false, "Emit GitHub Actions workflow annotations on stdout instead of the text summary")
	viewAuditCmd.Flags().StringVar(&viewAuditGitLab, "gitlab", "", "Write a GitLab Code Quality (CodeClimate) report to this file (e.g. gl-code-quality-report.json)")
	viewAuditCmd.Flags().StringVar(&viewAuditRepoRoot, "repo-root", "", "Repo root: where .risk-guard.yml lives and what file paths are relative to (defaults to $GITHUB_WORKSPACE/$CI_PROJECT_DIR then CWD)")
	viewAuditCmd.Flags().StringArrayVar(&viewAuditPackages, "package", nil, "Show only findings for this package; matches the bare name, package/<eco>/<name>, <eco>/<name>, or <name>@<version>. Repeat to keep several packages")
	registerLevelFlag(viewAuditCmd)
	auditCmd.AddCommand(viewAuditCmd)
}

// runViewAudit reads a report off disk and hands it to the same renderReport the
// run uses, so a saved SARIF replays the run's summary, findings, and verdict.
func runViewAudit(_ *cobra.Command, args []string) error {
	report, err := sarif.Open(args[0])
	if err != nil {
		return fmt.Errorf("reading SARIF: %w", err)
	}
	if err := ensurePackagesPresent(report, viewAuditPackages); err != nil {
		return err
	}
	root := resolveRepoRoot(viewAuditRepoRoot)
	mode, err := resolveWorkflowMode("", root)
	if err != nil {
		return err
	}
	levelFilter, err := levelFilterFor(findingLevel)
	if err != nil {
		return err
	}
	return renderReport(report, mode, viewAuditGitHub, viewAuditGitLab, root, args[0], levelFilter, packageFilterFor(viewAuditPackages))
}

// ensurePackagesPresent errors when a --package spec names no package that appears
// in the report, so a typo (e.g. "pdfjs-distsdf") fails loudly instead of
// rendering a misleading empty, all-clear view. A clean package leaves no result
// in the SARIF (only findings are stored), so "not present" here means "this
// report records no findings for it".
func ensurePackagesPresent(report *sarif.Report, specs []string) error {
	if len(specs) == 0 {
		return nil
	}

	forms := map[string]bool{} // every match-form of every package present
	names := map[string]bool{} // human names, for the "packages present" hint
	for _, run := range report.Runs {
		keys := map[string]bool{}
		for _, res := range run.Results {
			if k := packageFromResult(res); k != "" {
				keys[k] = true
			}
		}
		for k := range keys {
			names[humanPackageName(k)] = true
			for _, form := range packageMatchForms(k) {
				forms[strings.ToLower(form)] = true
			}
		}
	}

	var missing []string
	for _, s := range specs {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" && !forms[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	avail := make([]string, 0, len(names))
	for n := range names {
		avail = append(avail, n)
	}
	sort.Strings(avail)
	present := "(none)"
	if len(avail) > 0 {
		present = strings.Join(avail, ", ")
	}
	return fmt.Errorf("package not found in report: %s\npackages present: %s",
		strings.Join(missing, ", "), present)
}

// packageFilterFor builds a predicate that keeps a finding whose package
// logical-location key matches any of the given specs, or nil when no spec was
// given (keep every package). A spec matches by exact, case-insensitive
// comparison against the package's identifying forms (see packageMatchForms), so
// the same package can be named by its bare name, its full logical location, its
// ecosystem/name, or its name@version — whichever the operator has in hand.
func packageFilterFor(specs []string) func(string) bool {
	want := make(map[string]bool, len(specs))
	for _, s := range specs {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			want[s] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	return func(pkgKey string) bool {
		for _, form := range packageMatchForms(pkgKey) {
			if want[strings.ToLower(form)] {
				return true
			}
		}
		return false
	}
}

// packageMatchForms lists the strings a --package spec may use to name the
// package identified by pkgKey: the raw key, the key without its ?version=
// query, the ecosystem/name, the bare name, and name@version. A key
// parseKeyIdentity can't decode still matches on its raw form.
func packageMatchForms(pkgKey string) []string {
	if pkgKey == "" {
		return nil
	}
	forms := []string{pkgKey}
	if base, _, ok := strings.Cut(pkgKey, "?"); ok {
		forms = append(forms, base)
	}
	eco, name, version := parseKeyIdentity(pkgKey)
	if name != "" {
		forms = append(forms, name)
		if eco != "" {
			forms = append(forms, eco+"/"+name)
		}
		if version != "" {
			forms = append(forms, name+"@"+version)
		}
	}
	return forms
}

// keepMatchingPackages returns only the findings whose package satisfies keep,
// preserving order. It backs the --package filter on `audit view`.
func keepMatchingPackages(findings []ghFinding, keep func(string) bool) []ghFinding {
	out := make([]ghFinding, 0, len(findings))
	for _, f := range findings {
		if keep(f.pkg) {
			out = append(out, f)
		}
	}
	return out
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
