package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"github.com/charmbracelet/huh"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

// finding is the triage-facing projection of a SARIF Result: the entity the
// finding belongs to (in expected_failures key form), the check code, and a
// human-readable summary for the prompt.
type finding struct {
	EntityKey string
	CheckCode string
	Level     string
	Message   string
}

func collectInitFindings(report *sarif.Report, level string) []finding {
	var out []finding
	for _, run := range report.Runs {
		for _, res := range run.Results {
			lvl := ""
			if res.Level != nil {
				lvl = *res.Level
			}
			// Triage runs one SARIF level at a time: init triages "error"
			// findings into expected_failures and "warning" findings into
			// expected_warnings. Notes and info are left for hand-editing.
			if lvl != level {
				continue
			}
			code := ""
			if res.RuleID != nil {
				code = *res.RuleID
			}
			if code == "" {
				continue
			}
			msg := ""
			if res.Message.Text != nil {
				msg = *res.Message.Text
			}
			out = append(out, finding{
				EntityKey: entityKeyForResult(res),
				CheckCode: code,
				Level:     lvl,
				Message:   msg,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].EntityKey != out[j].EntityKey {
			return out[i].EntityKey < out[j].EntityKey
		}
		return out[i].CheckCode < out[j].CheckCode
	})
	return out
}

// entityKeyForResult maps a SARIF Result's logical location back to the
// policy key used in expected_failures: "root" for the local-source analysis
// (whose AnalysisID has a "source/" prefix) and the package key otherwise.
// Falls back to "root" when no logical location is attached.
func entityKeyForResult(res *sarif.Result) string {
	for _, loc := range res.Locations {
		if loc == nil {
			continue
		}
		for _, ll := range loc.LogicalLocations {
			if ll == nil || ll.Name == nil {
				continue
			}
			name := *ll.Name
			if strings.HasPrefix(name, "source/") {
				return "root"
			}
			return name
		}
	}
	return "root"
}

type triageDecision int

const (
	triageNone triageDecision = iota
	triageIgnoreAll
	triageReviewEach
)

// triageTarget describes which findings a triage pass is for: the noun used in
// the prompt ("blocking finding", "warning") and the config section the picks
// land in ("expected_failures", "expected_warnings").
type triageTarget struct {
	noun    string
	section string
}

var (
	triageFailures = triageTarget{noun: "blocking finding", section: "expected_failures"}
	triageWarnings = triageTarget{noun: "warning", section: "expected_warnings"}
)

func pluralize(noun string, n int) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}

// triageInitFindings prompts for how to handle a set of same-level findings and
// returns the entries to record in the target section. Returns nil (add
// nothing) when the user keeps defaults or reviews and ignores none.
func triageInitFindings(findings []finding, t triageTarget) (map[string]policy.ExpectedFailureV2, error) {
	decision, err := chooseTriageMode(len(findings), t)
	if err != nil {
		return nil, err
	}
	switch decision {
	case triageIgnoreAll:
		return buildExpectedFailures(findings), nil
	case triageReviewEach:
		picked := map[string]map[string]struct{}{}
		if err := reviewEachInto(findings, picked); err != nil {
			return nil, err
		}
		if len(picked) == 0 {
			return nil, nil
		}
		return groupedToExpectedFailures(picked), nil
	default:
		return nil, nil
	}
}

func chooseTriageMode(n int, t triageTarget) (triageDecision, error) {
	var choice string
	err := huh.NewSelect[string]().
		Title(fmt.Sprintf("Found %d %s. What would you like to do?", n, pluralize(t.noun, n))).
		Options(
			huh.NewOption(fmt.Sprintf("Ignore all (add %s for every %s)", t.section, t.noun), "ignore-all"),
			huh.NewOption("Review each one", "review"),
			huh.NewOption("Keep defaults (don't add anything)", "none"),
		).
		Value(&choice).
		Run()
	if err != nil {
		return triageNone, err
	}
	switch choice {
	case "ignore-all":
		return triageIgnoreAll, nil
	case "review":
		return triageReviewEach, nil
	default:
		return triageNone, nil
	}
}

// addPick records a (entity, check) pair into the picked set, creating the
// per-entity inner map on first use.
func addPick(picked map[string]map[string]struct{}, entity, check string) {
	if picked[entity] == nil {
		picked[entity] = map[string]struct{}{}
	}
	picked[entity][check] = struct{}{}
}

// reviewEachInto prompts the user per finding and records each "ignore" pick
// into picked. Unlike reviewEach it does not touch a policy, so callers that
// merge (rather than overwrite) expected_failures can reuse the prompt loop.
func reviewEachInto(findings []finding, picked map[string]map[string]struct{}) error {
	for _, f := range findings {
		var pick string
		err := huh.NewSelect[string]().
			Title(fmt.Sprintf("%s — %s (%s)", f.EntityKey, f.CheckCode, f.Level)).
			Description(f.Message).
			Options(
				huh.NewOption("Ignore (add to expected_failures)", "ignore"),
				huh.NewOption("Keep default", "keep"),
			).
			Value(&pick).
			Run()
		if err != nil {
			return err
		}
		if pick == "ignore" {
			addPick(picked, f.EntityKey, f.CheckCode)
		}
	}
	return nil
}

// mergeExpectedFailures unions picked entries onto pol.ExpectedFailures:
// existing entries are preserved and their check codes deduped + re-sorted with
// the new ones. reason is applied only to entities that don't already carry one,
// so hand-written reasons survive a merge.
func mergeExpectedFailures(pol *policy.Policy, picked map[string]map[string]struct{}, reason string) {
	if len(picked) == 0 {
		return
	}
	if pol.ExpectedFailures == nil {
		pol.ExpectedFailures = make(map[string]policy.ExpectedFailureV2, len(picked))
	}
	for entity, codeSet := range picked {
		ef := pol.ExpectedFailures[entity]
		set := map[string]struct{}{}
		for _, c := range ef.Checks {
			set[c] = struct{}{}
		}
		for c := range codeSet {
			set[c] = struct{}{}
		}
		codes := make([]string, 0, len(set))
		for c := range set {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		ef.Checks = codes
		if ef.Reason == "" {
			ef.Reason = reason
		}
		pol.ExpectedFailures[entity] = ef
	}
}

func buildExpectedFailures(findings []finding) map[string]policy.ExpectedFailureV2 {
	grouped := map[string]map[string]struct{}{}
	for _, f := range findings {
		if grouped[f.EntityKey] == nil {
			grouped[f.EntityKey] = map[string]struct{}{}
		}
		grouped[f.EntityKey][f.CheckCode] = struct{}{}
	}
	return groupedToExpectedFailures(grouped)
}

func groupedToExpectedFailures(grouped map[string]map[string]struct{}) map[string]policy.ExpectedFailureV2 {
	out := make(map[string]policy.ExpectedFailureV2, len(grouped))
	for key, codeSet := range grouped {
		codes := make([]string, 0, len(codeSet))
		for c := range codeSet {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		out[key] = policy.ExpectedFailureV2{
			Checks: codes,
			Reason: "Acknowledged during risk-guard init",
		}
	}
	return out
}
