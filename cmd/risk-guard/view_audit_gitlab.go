package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// codeClimateIssue is one entry of a GitLab Code Quality report. The schema is
// the CodeClimate subset GitLab requires: it renders these inline on the merge
// request diff gutter (when the file/line is in the diff) and in the MR widget.
// Unlike GitHub annotations, GitLab consumes a file artifact, not parsed stdout.
type codeClimateIssue struct {
	Description string     `json:"description"`
	CheckName   string     `json:"check_name"`
	Fingerprint string     `json:"fingerprint"`
	Severity    string     `json:"severity"`
	Location    ccLocation `json:"location"`
}

type ccLocation struct {
	Path  string  `json:"path"`
	Lines ccLines `json:"lines"`
}

type ccLines struct {
	Begin int `json:"begin"`
}

// renderGitLab writes the findings as a GitLab Code Quality (CodeClimate) JSON
// array to w. It is the GitLab analog of renderGitHub: same finding collection,
// subject resolution, level filter, and message wording — but emitted as a
// report file GitLab uploads (artifacts:reports:codequality) rather than stdout
// workflow commands, because GitLab has no inline-log annotation mechanism.
//
// CodeClimate requires a location.path; a finding with no resolvable physical
// location cannot be represented, so it is skipped with a warning to warn.
// repoRoot relativizes absolute paths (see resolveRepoRoot / relativizePath).
func renderGitLab(w io.Writer, warn io.Writer, report *sarif.Report, level string, packages []string, repoRoot string) error {
	pkgFilter := stringSet(packages)
	levelFilter, err := normalizeLevelFilter(level)
	if err != nil {
		return err
	}

	findings, skipped := collectGHFindings(report, pkgFilter, levelFilter)
	for _, rule := range skipped {
		_, _ = fmt.Fprintf(warn, "warning: skipping result with no package logical-location (rule=%s)\n", rule)
	}

	root := resolveRepoRoot(repoRoot)
	issues := make([]codeClimateIssue, 0, len(findings))
	for _, gf := range findings {
		relPath := relativizePath(gf.f.File, root)
		if relPath == "" || relPath == "." {
			// CodeClimate has no way to represent a pathless issue; drop it
			// rather than emit an invalid report GitLab would reject. "." is
			// RepoRootURI — a directory anchor for results with no physical
			// location (see EnsurePhysicalLocations), not a real file path.
			_, _ = fmt.Fprintf(warn, "warning: skipping finding with no file location (subject=%s rule=%s)\n", gf.subject, gf.f.RuleID)
			continue
		}
		begin := gf.f.Line
		if begin <= 0 {
			begin = 1
		}
		issues = append(issues, codeClimateIssue{
			Description: gitlabDescription(gf),
			CheckName:   gf.f.RuleID,
			Fingerprint: codeClimateFingerprint(gf.pkg, gf.f.RuleID, relPath, begin),
			Severity:    gitlabSeverity(gf.f.Level),
			Location:    ccLocation{Path: relPath, Lines: ccLines{Begin: begin}},
		})
	}

	// Deterministic order so re-runs produce byte-identical reports and GitLab's
	// branch-to-branch comparison stays stable.
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Location.Path != issues[j].Location.Path {
			return issues[i].Location.Path < issues[j].Location.Path
		}
		if issues[i].Location.Lines.Begin != issues[j].Location.Lines.Begin {
			return issues[i].Location.Lines.Begin < issues[j].Location.Lines.Begin
		}
		if issues[i].CheckName != issues[j].CheckName {
			return issues[i].CheckName < issues[j].CheckName
		}
		return issues[i].Fingerprint < issues[j].Fingerprint
	})

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(issues)
}

// gitlabDescription builds the single-line description GitLab shows in the diff
// gutter and MR widget. It mirrors formatGithubAnnotation's body — "<subject> —
// <rationale>" with non-redundant evidence — so GitHub and GitLab read
// identically, but flattened to one line (the gutter has no multi-line layout).
func gitlabDescription(gf ghFinding) string {
	rationale, evidence, note := splitMessageParts(gf.f.Message)
	rationale = stripSubjectPrefix(rationale, gf.pkg)
	evidence = dedupeEvidence(evidence, rationale, gf.pkg)

	var b strings.Builder
	if gf.subject != "" {
		b.WriteString(gf.subject)
		b.WriteString(" — ")
	}
	b.WriteString(rationale)
	for _, e := range evidence {
		b.WriteString("; ")
		b.WriteString(e)
	}
	if note != "" {
		b.WriteString(" (Note: ")
		b.WriteString(note)
		b.WriteString(")")
	}
	return strings.TrimSpace(b.String())
}

// gitlabSeverity maps our view level to a CodeClimate severity. GitLab accepts
// info|minor|major|critical|blocker; blocking (error) findings become critical
// so they stand out in the MR widget without claiming the "blocker" tier, which
// we reserve for nothing currently.
func gitlabSeverity(viewLevel string) string {
	switch viewLevel {
	case levelError:
		return "critical"
	case levelWarning:
		return "major"
	case levelNote:
		return "minor"
	default:
		return "info"
	}
}

// codeClimateFingerprint produces the stable, unique fingerprint GitLab uses to
// track an issue across pipelines. It is deterministic in the finding's
// identity (package, rule, file, line) so an unchanged finding keeps the same
// fingerprint, and NUL-separates the parts so distinct findings can't collide
// by concatenation.
func codeClimateFingerprint(pkg, ruleID, relPath string, line int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%s\x00%d", pkg, ruleID, relPath, line))
	return fmt.Sprintf("%x", sum)
}
