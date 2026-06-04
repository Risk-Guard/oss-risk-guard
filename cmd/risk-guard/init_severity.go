package main

import (
	"fmt"
	"os"
	"sort"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

// severityTuneTarget is one prompt in the tuning pass: a distinct check that
// fired, its current (audit-time) severity, and how many findings it produced.
type severityTuneTarget struct {
	code    string
	current policy.Severity
	count   int
}

// severityTuneTargets collapses the fired findings into one target per check
// code, sorted for a stable prompt order. A code that fired at error level for
// any entity is "currently blocking"; otherwise it's "currently warning".
func severityTuneTargets(findings, warnings []finding) []severityTuneTarget {
	current := map[string]policy.Severity{}
	count := map[string]int{}
	for _, f := range findings { // error-level
		current[f.CheckCode] = policy.SeverityBlocking
		count[f.CheckCode]++
	}
	for _, f := range warnings { // warning-level
		if _, ok := current[f.CheckCode]; !ok {
			current[f.CheckCode] = policy.SeverityWarning
		}
		count[f.CheckCode]++
	}
	codes := make([]string, 0, len(current))
	for c := range current {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	out := make([]severityTuneTarget, 0, len(codes))
	for _, c := range codes {
		out = append(out, severityTuneTarget{code: c, current: current[c], count: count[c]})
	}
	return out
}

// severityOptions builds the three-way blocking/warning/ignore choice, tagging
// the check's current severity so the user can see what they're changing from.
func severityOptions(current policy.Severity) []huh.Option[policy.Severity] {
	mk := func(sev policy.Severity, label string) huh.Option[policy.Severity] {
		if sev == current {
			label += "   (current)"
		}
		return huh.NewOption(label, sev)
	}
	return []huh.Option[policy.Severity]{
		mk(policy.SeverityBlocking, "Blocking — fail the audit when this check fires"),
		mk(policy.SeverityWarning, "Warning — report it, but don't fail the audit"),
		mk(policy.SeverityIgnore, "Ignore — suppress this check entirely"),
	}
}

// tuneCheckSeverities walks every check that fired (at error or warning level)
// and lets the user set its severity. Picks that differ from the audit-time
// default are recorded in pol.Severity as check/<CODE> rules. The returned
// code→severity map lets the caller re-evaluate the findings so the triage
// counts that follow reflect these choices, not the audit-time levels.
func tuneCheckSeverities(findings, warnings []finding, pol *policy.Policy) (map[string]policy.Severity, error) {
	targets := severityTuneTargets(findings, warnings)
	choices := make(map[string]policy.Severity, len(targets))
	if len(targets) == 0 {
		return choices, nil
	}

	bold := color.New(color.Bold).FprintfFunc()
	fmt.Fprintln(os.Stderr)
	bold(os.Stderr, "Set how each flagged check affects the audit (%d %s).\n", len(targets), pluralize("check", len(targets)))
	fmt.Fprintf(os.Stderr, "Your choices are saved to %s under `severity:`.\n\n", initFileName)

	changed := 0
	for i, t := range targets {
		rationale, err := whyShouldICare(t.code)
		if err != nil {
			return nil, err
		}
		desc := rationale.why
		if rationale.stat != "" {
			desc += "\n↳ " + rationale.stat
		}
		desc += "\n↑/↓ to move · enter to confirm"
		chosen := t.current
		if err := huh.NewSelect[policy.Severity]().
			Title(fmt.Sprintf("[%d of %d checks to review]\n%s — %d %s · currently %s", i+1, len(targets), t.code, t.count, pluralize("finding", t.count), t.current)).
			Description(desc).
			Options(severityOptions(t.current)...).
			Value(&chosen).
			Run(); err != nil {
			return nil, err
		}
		choices[t.code] = chosen
		if chosen != t.current {
			setCheckSeverity(pol, t.code, chosen)
			echoChoice("%s: %s → %s", t.code, t.current, chosen)
			changed++
		}
	}
	if changed == 0 {
		echoGroupDone("Severity reviewed — kept all defaults")
	} else {
		echoGroupDone("Severity updated — %d %s changed, saved to %s", changed, pluralize("check", changed), initFileName)
	}

	// Only checks that produced findings are surfaced for review; point the user
	// at the full catalog so they know the rest exist and how to inspect them.
	allChecks, _ := dag_builder.GetAllCheckMetadata(localdag.Builder)
	if other := len(allChecks) - len(targets); other > 0 {
		fmt.Fprintln(os.Stderr, color.HiBlackString(
			"%d other %s weren't flagged today, so weren't reviewed.", other, pluralize("check", other)))
		fmt.Fprintf(os.Stderr, "%s %s\n",
			color.HiBlackString("See every check with"),
			color.CyanString("risk-guard policy checks"))
	}
	return choices, nil
}

// setCheckSeverity records a per-check severity rule (key "check/<CODE>") in the
// policy, creating the severity map on first use.
func setCheckSeverity(pol *policy.Policy, code string, sev policy.Severity) {
	if pol.Severity == nil {
		pol.Severity = map[string]policy.SeverityValue{}
	}
	pol.Severity["check/"+code] = policy.SeverityValue{
		Severity: sev,
		Reason:   "Set during risk-guard init",
	}
}

// applySeverityChoices rewrites the in-memory report's result levels to match
// the tuned severities so the triage render and recomputed counts reflect the
// user's choices. Ignored checks become level "none", dropping them from both
// the blocking and warning sections. Results for checks that weren't tuned are
// left untouched. The on-disk SARIF (already written) is intentionally not
// changed — it is the audit artifact; a later scan re-evaluates with the policy.
func applySeverityChoices(report *sarif.Report, choices map[string]policy.Severity) {
	if report == nil {
		return
	}
	for _, run := range report.Runs {
		for _, res := range run.Results {
			sev, ok := choices[derefString(res.RuleID)]
			if !ok {
				continue
			}
			lvl := severityToLevel(sev)
			res.Level = &lvl
		}
	}
}

// severityToLevel maps a policy severity to the SARIF level init's triage reads.
func severityToLevel(sev policy.Severity) string {
	switch sev {
	case policy.SeverityBlocking:
		return levelError
	case policy.SeverityWarning:
		return levelWarning
	default:
		return "none"
	}
}
