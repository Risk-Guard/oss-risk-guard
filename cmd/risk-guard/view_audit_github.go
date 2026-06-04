package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// runIDByPkg builds an index from the package key (as appears in
// result.locations[*].logicalLocations[*].name) back to its Run's
// AutomationDetails.ID. Used so selectFindingsByLevel can resolve a human subject for
// each finding even though findings are keyed on package name.
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

// ghFinding is a finding paired with the resolved human subject it belongs to,
// ready to be ordered and rendered into an annotation or summary row.
type ghFinding struct {
	subject string
	runID   string
	pkg     string
	f       auditFinding
}

// emitGitHubAnnotations writes the GitHub Actions workflow commands for a
// finding set (ordered least-to-most severe so blocking findings land last, next
// to the step's failure line) and appends the uncapped job-summary table. It is
// the githubPrinter's sink, fed the same selectFindingsByLevel output for both `run` and
// `view-audit`, so both produce identical annotations for the same findings.
// Diagnostics go to warn so the GH runner doesn't parse them as annotations.
func emitGitHubAnnotations(w io.Writer, warn io.Writer, findings []ghFinding, repoRoot string) error {
	// Errors last: rank 0 (error) sorts after rank 3 (info). Within a severity,
	// keep a subject's findings together, then order by rule for determinism.
	sort.SliceStable(findings, func(i, j int) bool {
		if ri, rj := levelRank(findings[i].f.Level), levelRank(findings[j].f.Level); ri != rj {
			return ri > rj
		}
		if findings[i].subject != findings[j].subject {
			return findings[i].subject < findings[j].subject
		}
		return findings[i].f.RuleID < findings[j].f.RuleID
	})

	root := resolveRepoRoot(repoRoot)
	for _, gf := range findings {
		if _, err := fmt.Fprintln(w, formatGithubAnnotation(gf.runID, gf.pkg, gf.f, root)); err != nil {
			return err
		}
	}

	if err := writeGitHubStepSummaryFindings(findings); err != nil {
		// A summary-write failure (e.g. the 1 MiB cap) must not fail the run;
		// the annotations already carried the findings.
		_, _ = fmt.Fprintf(warn, "warning: writing job summary: %v\n", err)
	}
	return nil
}

// formatGithubAnnotation builds a single ::level workflow command whose message
// is self-contained and reads top-down: "<subject> — <finding>", then any
// non-redundant detail as indented bullets, then an optional note. The subject
// leads the message because GitHub shows only the message body inline in the
// log — the title= property is visible only in the run-summary banner.
//
// runID is the owning Run's AutomationDetails.ID; pkgKey is the package
// logical-location. root relativizes an absolute file path; paths outside the
// root drop the file= segment.
func formatGithubAnnotation(runID, pkgKey string, f auditFinding, root string) string {
	subject := annotationSubject(runID, pkgKey)

	rationale, evidence, note := splitMessageParts(f.Message)
	rationale = stripSubjectPrefix(rationale, pkgKey)
	evidence = dedupeEvidence(evidence, rationale, pkgKey)

	var body strings.Builder
	if subject != "" {
		body.WriteString(subject)
		body.WriteString(" — ")
	}
	body.WriteString(rationale)
	for _, e := range evidence {
		body.WriteString("\n  • ")
		body.WriteString(e)
	}
	if note != "" {
		body.WriteString("\n  Note: ")
		body.WriteString(note)
	}

	// Title is banner-only; tag it with the subject so the banner is scannable.
	title := f.Title
	if subject != "" {
		title = f.Title + " · " + subject
	}

	var fields []string
	if relFile := relativizePath(f.File, root); relFile != "" {
		fields = append(fields, "file="+githubEscapeProperty(relFile))
		if f.Line > 0 {
			fields = append(fields, fmt.Sprintf("line=%d", f.Line))
		}
	}
	fields = append(fields, "title="+githubEscapeTitle(title))

	return fmt.Sprintf("::%s %s::%s", githubLevel(f.Level), strings.Join(fields, ","), githubEscapeData(body.String()))
}

// annotationSubject resolves the human-readable thing a finding is about: the
// local repository for source findings, otherwise the package (name@version).
func annotationSubject(runID, pkgKey string) string {
	if runID == "local-source" || strings.HasPrefix(pkgKey, "source/") {
		return "your repository"
	}
	if h := humanPackageName(pkgKey); h != pkgKey {
		return h
	}
	if runID != "" && runID != "local-source" {
		return runID
	}
	return pkgKey
}

// splitMessageParts reverses buildMessage (src/lib/common/sarif/convert.go),
// peeling the trailing "Note:" and "Evidence:" blocks back out of the combined
// SARIF message so each part can be rendered distinctly.
func splitMessageParts(msg string) (rationale string, evidence []string, note string) {
	rest := msg
	if i := strings.LastIndex(rest, "\n\nNote: "); i >= 0 {
		note = strings.TrimSpace(rest[i+len("\n\nNote: "):])
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "\n\nEvidence:"); i >= 0 {
		block := rest[i+len("\n\nEvidence:"):]
		rest = rest[:i]
		for ln := range strings.SplitSeq(block, "\n") {
			ln = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ln), "- "))
			if ln != "" {
				evidence = append(evidence, ln)
			}
		}
	}
	return strings.TrimSpace(rest), evidence, note
}

// stripSubjectPrefix removes a leading "eco/name:" or "eco/name@version:" from
// a line when it matches pkgKey, since the rendered subject already carries it.
func stripSubjectPrefix(line, pkgKey string) string {
	eco, name, version := parseKeyIdentity(pkgKey)
	if eco == "" || name == "" {
		return line
	}
	prefixes := []string{eco + "/" + name + ": "}
	if version != "" {
		prefixes = append(prefixes, eco+"/"+name+"@"+version+": ")
	}
	for _, p := range prefixes {
		if len(line) >= len(p) && strings.EqualFold(line[:len(p)], p) {
			return strings.TrimSpace(line[len(p):])
		}
	}
	return line
}

// dedupeEvidence drops evidence items that merely restate the headline (the
// common case: a one-item evidence list equal to the rationale) and collapses
// exact duplicates. Each item is subject-prefix-stripped for a clean display
// and for fair comparison against the (already stripped) rationale.
func dedupeEvidence(evidence []string, rationale, pkgKey string) []string {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	seen := map[string]bool{norm(rationale): true}
	var out []string
	for _, e := range evidence {
		stripped := stripSubjectPrefix(e, pkgKey)
		n := norm(stripped)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, stripped)
	}
	return out
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

// githubEscapeData encodes the message body of a workflow command. Per
// @actions/toolkit's escapeData: only %, CR, LF need encoding — `,` and `:`
// have no special meaning after the framing `::` and GitHub does not decode
// %2C/%3A there. % must be replaced first so our own escapes aren't re-encoded.
func githubEscapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// githubEscapeProperty encodes a key=value property value. Mirrors
// @actions/toolkit's escapeProperty: escapeData plus `,` (param separator) and
// `:` (terminates the property list before the message body).
func githubEscapeProperty(s string) string {
	s = githubEscapeData(s)
	s = strings.ReplaceAll(s, ",", "%2C")
	s = strings.ReplaceAll(s, ":", "%3A")
	return s
}

// githubEscapeTitle collapses newlines (titles must be single-line) then
// encodes as a property value.
func githubEscapeTitle(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return githubEscapeProperty(s)
}

// resolveRepoRoot returns the effective root for relativizing file paths.
// Precedence: explicit arg, then the CI checkout dir (GitHub's
// $GITHUB_WORKSPACE, then GitLab's $CI_PROJECT_DIR), then CWD. Both renderers
// (GitHub annotations, GitLab Code Quality) share this resolution.
func resolveRepoRoot(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
		return ws
	}
	if ws := os.Getenv("CI_PROJECT_DIR"); ws != "" {
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
