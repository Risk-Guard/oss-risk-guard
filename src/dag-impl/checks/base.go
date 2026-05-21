package checks

import (
	"risk-guard/src/category"
	"risk-guard/src/lib/common/storage"

	dag_impl "risk-guard/src/dag-impl"
)

// BaseCheckNode provides common fields and all boilerplate methods for check nodes.
// Embed this struct to get Kind(), GetCode(), GetDescription(), GetCategories(), and CreateSkippedOutput().
//
// All fields serialize into the catalog (go run src/server/main.go meta catalog) and are
// visible to customers evaluating the product. Write for a non-technical security audience.
type BaseCheckNode struct {
	// UPPER_SNAKE_CASE identifier. Must be unique across all checks.
	Code string `json:"code"`

	// Single sentence stating the condition this check detects.
	// Must read naturally as: "This check fires when: <Description>".
	// State the observable fact only — consequences belong in Categories.
	Description string `json:"description"`

	// One sentence explaining the security or operational risk this check exists to detect.
	// Omit when the Description (and Outcomes, if present) already make the risk self-evident.
	WhyThisMatters string `json:"why_this_matters,omitempty"`

	// Risk category → sentence explaining WHY this check belongs in that category.
	// The key determines policy enforcement; the value completes the sentence
	// "This check is in the <category> category because: <value>".
	// Do NOT restate the Description — explain the consequence or risk.
	Categories map[category.RiskCategory]string `json:"categories"`

	// What each check status means for this specific check.
	// Omit when the Description already makes outcomes self-evident.
	Outcomes storage.Outcomes `json:"outcomes,omitempty"`

	// Methodology, scope limitations, or default thresholds a customer needs to
	// interpret the result correctly. Use fmt.Sprintf for threshold defaults so
	// values stay in sync with code. One caveat per entry.
	Disclaimers []string `json:"disclaimers,omitempty"`

	// Configurable decision boundaries for threshold-based checks.
	// Serialized into catalog and check output for customer visibility.
	Thresholds map[string]any `json:"thresholds,omitempty"`
}

func (b *BaseCheckNode) Kind() string {
	return "check"
}

func (b *BaseCheckNode) GetCode() string {
	return b.Code
}

func (b *BaseCheckNode) GetDescription() string {
	return b.Description
}

func (b *BaseCheckNode) GetWhyThisMatters() string {
	return b.WhyThisMatters
}

func (b *BaseCheckNode) GetCategories() map[category.RiskCategory]string {
	return b.Categories
}

func (b *BaseCheckNode) GetOutcomes() storage.Outcomes {
	return b.Outcomes
}

func (b *BaseCheckNode) GetDisclaimers() []string {
	return b.Disclaimers
}

func (b *BaseCheckNode) GetThresholds() map[string]any {
	return b.Thresholds
}

func (b *BaseCheckNode) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewSkippedOutput(b.Code, reason, input)
}
