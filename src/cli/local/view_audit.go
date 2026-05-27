package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/spf13/cobra"
)

var (
	viewAuditLevel    string
	viewAuditPackages []string
	viewAuditGitHub   bool
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

Examples:
  risk-guard-local view-audit audit.sarif
  risk-guard-local view-audit audit.sarif --level error
  risk-guard-local view-audit audit.sarif --package lodash --package express
  risk-guard-local view-audit audit.sarif --github`,
	Args: cobra.ExactArgs(1),
	RunE: runViewAudit,
}

func init() {
	viewAuditCmd.Flags().StringVar(&viewAuditLevel, "level", "all", "Filter findings by level: error, warning, note, info, all")
	viewAuditCmd.Flags().StringArrayVar(&viewAuditPackages, "package", nil, "Filter to specific package names (repeatable)")
	viewAuditCmd.Flags().BoolVar(&viewAuditGitHub, "github", false, "Emit GitHub Actions workflow annotations instead of human-readable summary")
	viewAuditCmd.Flags().StringVar(&viewAuditRepoRoot, "repo-root", "", "Root to make file paths relative to (defaults to $GITHUB_WORKSPACE then CWD); used with --github")
	rootCmd.AddCommand(viewAuditCmd)
}

func runViewAudit(_ *cobra.Command, args []string) error {
	report, err := sarif.Open(args[0])
	if err != nil {
		return fmt.Errorf("reading SARIF: %w", err)
	}
	if viewAuditGitHub {
		return renderGitHub(os.Stdout, os.Stderr, report, viewAuditLevel, viewAuditPackages, viewAuditRepoRoot)
	}
	return renderAudit(os.Stdout, report, viewAuditLevel, viewAuditPackages)
}

type auditFinding struct {
	Level   string // "error" | "warning" | "note" | "info"
	RuleID  string
	Title   string // rule short description, fallback to RuleID
	Message string // full multi-line rationale + evidence
	File    string // physical location URI, empty if absent
	Line    int    // physical location startLine, 0 if absent
}

const (
	levelError   = "error"
	levelWarning = "warning"
	levelNote    = "note"
	levelInfo    = "info" // user-facing label for SARIF "none"
)

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

func formatCounts(c levelCounts) string {
	parts := make([]string, 0, 4)
	for _, lc := range []struct {
		label string
		n     int
	}{
		{"error", c.Error},
		{"warning", c.Warning},
		{"note", c.Note},
		{"info", c.Info},
	} {
		if lc.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", lc.n, lc.label))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return ": " + strings.Join(parts, ", ")
}

type levelCounts struct{ Error, Warning, Note, Info int }

func countByLevel(fs []auditFinding) levelCounts {
	var c levelCounts
	for _, f := range fs {
		switch f.Level {
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
	return c
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

// normalizeLevel maps SARIF levels (including the bare "none") to the
// user-facing labels used throughout the view: error/warning/note/info.
func normalizeLevel(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case levelError:
		return levelError
	case levelNote:
		return levelNote
	case "none":
		return levelInfo
	case "", levelWarning:
		return levelWarning
	default:
		return levelWarning
	}
}

func normalizeLevelFilter(level string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(level))
	if f == "" {
		return "all", nil
	}
	switch f {
	case "all", levelError, levelWarning, levelNote, levelInfo:
		return f, nil
	case "none":
		return levelInfo, nil
	}
	return "", fmt.Errorf("invalid --level %q (want one of: all, error, warning, note, info)", level)
}

func levelRank(level string) int {
	switch level {
	case levelError:
		return 0
	case levelWarning:
		return 1
	case levelNote:
		return 2
	case levelInfo:
		return 3
	default:
		return 4
	}
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

// runIDByPkg builds an index from the package key (as appears in
// result.locations[*].logicalLocations[*].name) back to its Run's
// AutomationDetails.ID. Used so renderGitHub can prefix annotation titles with
// the analysis identifier even though findings are keyed on package name.
func runIDByPkg(report *sarif.Report) map[string]string {
	out := map[string]string{}
	for _, run := range report.Runs {
		if run.AutomationDetails == nil || run.AutomationDetails.ID == nil {
			continue
		}
		id := *run.AutomationDetails.ID
		for _, res := range run.Results {
			if pkg := packageFromResult(res); pkg != "" {
				if _, exists := out[pkg]; !exists {
					out[pkg] = id
				}
			}
		}
	}
	return out
}

// renderGitHub writes one GitHub Actions workflow command per finding to w.
// Skip-warnings and other non-annotation diagnostics go to warn so they don't
// get parsed by the GH runner as annotations. Findings whose SARIF carries
// physicalLocation produce annotations with file=…,line=…; the rest fall back
// to repo-level annotations (no file= segment).
//
// repoRoot resolution order: explicit arg, then $GITHUB_WORKSPACE, then CWD.
// Paths not contained in the resolved root are emitted without file= rather
// than as broken relative paths.
func renderGitHub(w io.Writer, warn io.Writer, report *sarif.Report, level string, packages []string, repoRoot string) error {
	pkgFilter := stringSet(packages)
	levelFilter, err := normalizeLevelFilter(level)
	if err != nil {
		return err
	}

	grouped, skipped := collectFindings(report, pkgFilter, levelFilter)
	for _, rule := range skipped {
		fmt.Fprintf(warn, "warning: skipping result with no package logical-location (rule=%s)\n", rule)
	}

	root := resolveRepoRoot(repoRoot)
	runIDs := runIDByPkg(report)

	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		findings := grouped[name]
		sort.SliceStable(findings, func(i, j int) bool {
			if findings[i].Level != findings[j].Level {
				return levelRank(findings[i].Level) < levelRank(findings[j].Level)
			}
			return findings[i].RuleID < findings[j].RuleID
		})
		runID := runIDs[name]
		for _, f := range findings {
			line := formatGithubAnnotation(runID, name, f, root)
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
	}
	return nil
}

// formatGithubAnnotation builds a single ::level workflow command. runID is the
// owning Run's AutomationDetails.ID and prefixes the title (omitted for the
// local-source Run). pkgKey is the package logical-location used as fallback.
// root is the repo root used to relativize an absolute file path; paths outside
// the root drop the file= segment.
func formatGithubAnnotation(runID, pkgKey string, f auditFinding, root string) string {
	ghLevel := githubLevel(f.Level)

	titleSubject := runID
	if titleSubject == "" {
		titleSubject = pkgKey
	}
	var title string
	if titleSubject == "" || titleSubject == "local-source" {
		title = githubEscapeTitle(f.Title)
	} else {
		title = githubEscapeTitle("[" + titleSubject + "] " + f.Title)
	}

	var fields []string
	if relFile := relativizePath(f.File, root); relFile != "" {
		fields = append(fields, "file="+relFile)
		if f.Line > 0 {
			fields = append(fields, fmt.Sprintf("line=%d", f.Line))
		}
	}
	fields = append(fields, "title="+title)

	message := githubEscapeMessage(f.Message)
	return fmt.Sprintf("::%s %s::%s", ghLevel, strings.Join(fields, ","), message)
}

func githubLevel(viewLevel string) string {
	switch viewLevel {
	case levelError:
		return "error"
	case levelWarning:
		return "warning"
	default:
		return "notice"
	}
}

// githubEscapeMessage encodes characters that have meaning in workflow commands.
// Per GitHub docs: %r→%25, then CR/LF/comma/colon. %r ordering matters so we
// don't double-encode our own escapes.
func githubEscapeMessage(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, ",", "%2C")
	s = strings.ReplaceAll(s, ":", "%3A")
	return s
}

// githubEscapeTitle is the message escaper minus newlines: titles must be
// single-line, so we collapse any newlines to spaces first.
func githubEscapeTitle(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return githubEscapeMessage(s)
}

// resolveRepoRoot returns the effective root for relativizing file paths.
func resolveRepoRoot(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
		return ws
	}
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}

// relativizePath returns a repo-relative path suitable for GitHub annotations.
// Relative paths (the common case for our SARIF) pass through unchanged.
// Absolute paths are made relative to root; if the result escapes the root
// (starts with ..) or filepath.Rel errors, returns "" so the caller omits file=.
func relativizePath(file, root string) string {
	if file == "" {
		return ""
	}
	if !filepath.IsAbs(file) {
		return file
	}
	if root == "" {
		return ""
	}
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(rel, "..") {
		return ""
	}
	return rel
}
