package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"

	"github.com/fatih/color"
)

// categoryOrder lists risk categories from most to least severe so the catalog
// leads with the families the default policy treats as blocking. Categories not
// listed here fall back to alphabetical order after these.
var categoryOrder = []category.RiskCategory{
	category.RiskCategoryCritical,
	category.RiskCategorySecurityVulnerability,
	category.RiskCategoryLicenseCompliance,
	category.RiskCategoryTitleAssurance,
	category.RiskCategoryContinuityAssurance,
}

const uncategorized = "(uncategorized)"

// renderCheckList produces a human-readable, colored catalog of every check the
// tool can run, grouped by risk category. The category headers are colored to
// mirror how the default policy grades them; a check with multiple categories is
// listed under each. It returns the full text so the caller can do a single
// checked write to stdout.
func renderCheckList(checks []dag_builder.CheckInfo) string {
	var b strings.Builder
	bold := color.New(color.Bold).Sprint
	b.WriteString(bold("Available checks") + "  " + color.HiBlackString("%d total", len(checks)) + "\n")

	byCategory := groupByCategory(checks)

	for _, cat := range orderedCategories(byCategory) {
		group := byCategory[cat]
		sort.Slice(group, func(i, j int) bool { return group[i].Code < group[j].Code })

		width := 0
		for _, c := range group {
			if len(c.Code) > width {
				width = len(c.Code)
			}
		}

		b.WriteString("\n" + categoryHeader(cat) + "\n")
		for _, c := range group {
			fmt.Fprintf(&b, "  %s  %s\n",
				color.New(color.Bold).Sprintf("%-*s", width, c.Code),
				color.HiBlackString("%s", c.Description))
			if c.Deprecated {
				fmt.Fprintf(&b, "  %-*s  %s\n", width, "", color.HiBlackString("(deprecated)"))
			}
		}
	}

	return b.String()
}

// groupByCategory buckets each check under every risk category it declares.
// Checks with no categories land under the uncategorized bucket.
func groupByCategory(checks []dag_builder.CheckInfo) map[string][]dag_builder.CheckInfo {
	out := map[string][]dag_builder.CheckInfo{}
	for _, c := range checks {
		if len(c.Categories) == 0 {
			out[uncategorized] = append(out[uncategorized], c)
			continue
		}
		for cat := range c.Categories {
			out[string(cat)] = append(out[string(cat)], c)
		}
	}
	return out
}

// orderedCategories returns the categories present in byCategory in display
// order: the known severity order first, then any unknown categories
// alphabetically, then the uncategorized bucket last.
func orderedCategories(byCategory map[string][]dag_builder.CheckInfo) []string {
	seen := map[string]bool{}
	var ordered []string
	for _, cat := range categoryOrder {
		if _, ok := byCategory[string(cat)]; ok {
			ordered = append(ordered, string(cat))
			seen[string(cat)] = true
		}
	}
	var rest []string
	for cat := range byCategory {
		if cat == uncategorized || seen[cat] {
			continue
		}
		rest = append(rest, cat)
	}
	sort.Strings(rest)
	ordered = append(ordered, rest...)
	if _, ok := byCategory[uncategorized]; ok {
		ordered = append(ordered, uncategorized)
	}
	return ordered
}

// categoryHeader renders a category as a bold, colored section header: critical
// and security risks red, the compliance/title/continuity families yellow.
func categoryHeader(cat string) string {
	attrs := []color.Attribute{color.Bold}
	switch category.RiskCategory(cat) {
	case category.RiskCategoryCritical, category.RiskCategorySecurityVulnerability:
		attrs = append(attrs, color.FgRed)
	case category.RiskCategoryTitleAssurance,
		category.RiskCategoryLicenseCompliance,
		category.RiskCategoryContinuityAssurance:
		attrs = append(attrs, color.FgYellow)
	}
	return color.New(attrs...).Sprint(cat)
}
