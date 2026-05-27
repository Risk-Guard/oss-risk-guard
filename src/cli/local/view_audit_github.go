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
		// Skip-warnings are diagnostic; a stderr write failure shouldn't abort
		// annotation emission.
		_, _ = fmt.Fprintf(warn, "warning: skipping result with no package logical-location (rule=%s)\n", rule)
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
