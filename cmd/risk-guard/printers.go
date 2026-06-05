package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// Printer renders findings for one output sink. Findings are fed one at a time
// via Print (each sink accumulates as it needs — text groups by subject, GitHub
// orders/caps, GitLab buffers a file), then Finalize emits.
type Printer interface {
	Print(f ghFinding)
	Finalize() error
}

// selectFindingsByLevel flattens a report into the findings to render, keeping
// only those whose level satisfies levelMatches. It resolves each finding's
// human subject, rule title, and provenance, so every output sink (text, GitHub,
// GitLab) and every command (run, view-audit, init) starts from the same finding
// shape — the level is preserved verbatim, so "which to show" is decided solely
// by levelMatches, never by mutating the level.
func selectFindingsByLevel(report *sarif.Report, levelMatches func(level string) bool) []ghFinding {
	if report == nil {
		return nil
	}
	runIDs := runIDByPkg(report)
	var out []ghFinding
	for _, run := range report.Runs {
		titles := ruleTitleIndex(run)
		for _, res := range run.Results {
			lvl := normalizeLevel(derefString(res.Level))
			if !levelMatches(lvl) {
				continue
			}
			pkg := packageFromResult(res)
			file, line := physicalFromResult(res)
			rule := derefString(res.RuleID)
			title := titles[rule]
			if title == "" {
				title = rule
			}
			out = append(out, ghFinding{
				subject: annotationSubject(runIDs[pkg], pkg),
				runID:   runIDs[pkg],
				pkg:     pkg,
				f: auditFinding{
					Level:   lvl,
					RuleID:  rule,
					Title:   title,
					Message: strings.TrimSpace(derefString(res.Message.Text)),
					File:    file,
					Line:    line,
				},
			})
		}
	}
	return out
}

// isLiveLevel is the default selection for both `run`/`checks` and `view-audit`:
// a finding's level is "live" when it is blocking or a warning, leaving
// acknowledged ("note") and ignored ("none") findings to the count tally only.
func isLiveLevel(level string) bool {
	return level == levelError || level == levelWarning
}

// levelEquals builds a predicate matching exactly one level. init's triage
// walkthrough uses it to show the blocking section, then the warning section,
// one acknowledge prompt each.
func levelEquals(want string) func(string) bool {
	return func(level string) bool { return level == want }
}

// reportPrinters builds the output sinks shared by `run` and `view-audit`, all
// rendering the same finding set:
//   - default: human text on stderr;
//   - --github: GitHub Actions annotations on stdout, replacing the text sink;
//   - --gitlab: a GitLab Code Quality report file, additive to either.
//
// Modes that suppress per-finding output (silent, disabled) return no printers;
// the scan still runs and SARIF is still written, only the annotations are quiet.
func reportPrinters(mode policy.WorkflowMode, toGitHub bool, gitlabPath, repoRoot string) []Printer {
	if !emitsAnnotations(mode) {
		return nil
	}
	var printers []Printer
	if toGitHub {
		printers = append(printers, &githubPrinter{w: os.Stdout, warn: os.Stderr, repoRoot: repoRoot})
	} else {
		printers = append(printers, newTextPrinter(os.Stderr))
	}
	if gitlabPath != "" {
		printers = append(printers, &gitlabPrinter{path: gitlabPath, warn: os.Stderr, repoRoot: repoRoot})
	}
	return printers
}

// renderFindings prints each finding to every printer, then finalizes them. The
// finding set is the caller's choice (a run passes its live findings, view-audit
// its --level filter); the printer set is built from flags. That's the whole
// pipeline: pick findings, pick printers, run this.
func renderFindings(findings []ghFinding, printers []Printer) error {
	for _, f := range findings {
		for _, p := range printers {
			p.Print(f)
		}
	}
	for _, p := range printers {
		if err := p.Finalize(); err != nil {
			return err
		}
	}
	return nil
}

// textPrinter renders findings as the human terminal report, grouped by subject.
type textPrinter struct {
	w         io.Writer
	bySubject map[string][]ghFinding
	order     []string
}

func newTextPrinter(w io.Writer) *textPrinter {
	return &textPrinter{w: w, bySubject: map[string][]ghFinding{}}
}

func (p *textPrinter) Print(f ghFinding) {
	if _, ok := p.bySubject[f.subject]; !ok {
		p.order = append(p.order, f.subject)
	}
	p.bySubject[f.subject] = append(p.bySubject[f.subject], f)
}

func (p *textPrinter) Finalize() error {
	sort.Strings(p.order)
	for _, subj := range p.order {
		group := p.bySubject[subj]
		sort.SliceStable(group, func(i, j int) bool {
			if ri, rj := levelRank(group[i].f.Level), levelRank(group[j].f.Level); ri != rj {
				return ri < rj // errors first
			}
			return group[i].f.RuleID < group[j].f.RuleID
		})
		afs := make([]auditFinding, len(group))
		for i, gf := range group {
			afs[i] = gf.f
		}
		if _, err := fmt.Fprintf(p.w, "\n%s — %d finding(s)%s\n", subj, len(group), formatCounts(countByLevel(afs))); err != nil {
			return err
		}
		for _, gf := range group {
			if err := p.writeFinding(gf.f); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeFinding writes one finding's human block to the printer's writer: a blank
// separator, the LEVEL + title, the rule code, the provenance (manifest/source
// file:line), and the wrapped message.
func (p *textPrinter) writeFinding(f auditFinding) error {
	w := p.w
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %-7s  %s\n", strings.ToUpper(f.Level), f.Title); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "           %s\n", f.RuleID); err != nil {
		return err
	}
	// Where the finding was discovered (the manifest that declared a dependency,
	// or the source file) — the provenance that makes it actionable. Skip the
	// synthetic repo-root anchor (commonsarif RepoRootURI = ".") that
	// EnsurePhysicalLocations stamps on findings with no real location.
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
	return nil
}

// githubPrinter renders findings as GitHub Actions annotations plus the job
// summary, reusing the same emitter as the view-audit GitHub renderer.
type githubPrinter struct {
	w        io.Writer
	warn     io.Writer
	repoRoot string
	findings []ghFinding
}

func (p *githubPrinter) Print(f ghFinding) { p.findings = append(p.findings, f) }

func (p *githubPrinter) Finalize() error {
	return emitGitHubAnnotations(p.w, p.warn, p.findings, p.repoRoot)
}

// gitlabPrinter writes findings to a GitLab Code Quality report file, reusing
// the same emitter as the view-audit GitLab renderer.
type gitlabPrinter struct {
	path     string
	warn     io.Writer
	repoRoot string
	findings []ghFinding
}

func (p *gitlabPrinter) Print(f ghFinding) { p.findings = append(p.findings, f) }

func (p *gitlabPrinter) Finalize() error {
	f, err := os.Create(p.path) //nolint:gosec // path is an operator-supplied --gitlab output file
	if err != nil {
		return fmt.Errorf("creating GitLab report %s: %w", p.path, err)
	}
	if err := emitGitLabIssues(f, p.warn, p.findings, nil, p.repoRoot); err != nil {
		_ = f.Close()
		return err
	}
	// Surface a Close error: a flush failure that only lands here (e.g. ENOSPC)
	// would otherwise leave a truncated report while the command reports success.
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing GitLab report %s: %w", p.path, err)
	}
	return nil
}
