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

func collectInitFindings(report *sarif.Report) []finding {
	var out []finding
	for _, run := range report.Runs {
		for _, res := range run.Results {
			lvl := ""
			if res.Level != nil {
				lvl = *res.Level
			}
			// Init triage only surfaces blocking (error) findings. Warnings,
			// notes, and info don't fail the build and just add noise to the
			// prompt; users who want to acknowledge them can edit
			// .risk-guard.yml by hand.
			if lvl != "error" {
				continue
			}
			code := ""
			if res.RuleID != nil {
				code = *res.RuleID
			}
			if code == "" {
				continue
			}
			// Synthetic audit-failure results (failureRun) are operational
			// errors, not policy findings — never offer them as expected_failures.
			if code == auditErrorRuleID {
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

func chooseTriageMode(n int) (triageDecision, error) {
	var choice string
	err := huh.NewSelect[string]().
		Title(fmt.Sprintf("Found %d finding(s). What would you like to do?", n)).
		Options(
			huh.NewOption("Ignore all (add expected_failures for every finding)", "ignore-all"),
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

func reviewEach(findings []finding, pol *policy.Policy) error {
	picked := map[string]map[string]struct{}{}
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
			if picked[f.EntityKey] == nil {
				picked[f.EntityKey] = map[string]struct{}{}
			}
			picked[f.EntityKey][f.CheckCode] = struct{}{}
		}
	}
	applyExpectedFailures(pol, picked)
	return nil
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

func applyExpectedFailures(pol *policy.Policy, picked map[string]map[string]struct{}) {
	if len(picked) == 0 {
		return
	}
	pol.ExpectedFailures = groupedToExpectedFailures(picked)
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
