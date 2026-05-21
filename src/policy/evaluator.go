package policy

import (
	"encoding/json"
	"fmt"
	"risk-guard/src/category"
	"risk-guard/src/models"
	"risk-guard/src/violations"
	"time"
)

type FindingKind string

const (
	FindingBlocking     FindingKind = "blocking"
	FindingWarning      FindingKind = "warning"
	FindingAcknowledged FindingKind = "acknowledged"
	FindingExpired      FindingKind = "expired"
	FindingIgnored      FindingKind = "ignored"
)

type PolicyStrategy string

const (
	PolicyStrategyMerged      PolicyStrategy = "merged"
	PolicyStrategyOverride    PolicyStrategy = "override"
	PolicyStrategyDefaultOnly PolicyStrategy = "default_only"
)

type PolicyBreakdown struct {
	Strategy PolicyStrategy `json:"strategy"`
	Repo     *PolicySummary `json:"repo"`
	Default  *PolicySummary `json:"default"`
	Applied  *PolicySummary `json:"applied"`
}

type Finding struct {
	Kind           FindingKind          `json:"kind"`
	Package        string               `json:"package"`
	Check          string               `json:"check"`
	Categories     []string             `json:"categories,omitempty"`
	Rationale      string               `json:"rationale"`
	Evidence       []string             `json:"evidence,omitempty"`
	DependencyPath []string             `json:"dependency_path"`
	RootLocation   *models.LocationInfo `json:"root_loc,omitempty"`
	Dev            bool                 `json:"dev,omitempty"`
	Note           string               `json:"note,omitempty"`
	MatchedRule    string               `json:"matched_rule,omitempty"`
}

type EvaluationResult struct {
	Status       string            `json:"status"`
	Source       string            `json:"source"`
	WorkflowMode WorkflowMode      `json:"workflow_mode,omitempty"`
	Error        string            `json:"error,omitempty"`
	Policies     *PolicyBreakdown  `json:"policies"`
	Findings     []Finding         `json:"findings"`
	Summary      EvaluationSummary `json:"summary"`
}

type PolicySummary struct {
	Version   int    `json:"version"`
	RuleCount int    `json:"rule_count"`
	RawYAML   string `json:"raw_yaml,omitempty"`
}

type EvaluationSummary struct {
	TotalPackages     int `json:"total_packages"`
	UnblockedPackages int `json:"unblocked_packages"`
	// Deprecated: Use UnblockedPackages instead.
	ChecksPassed int `json:"checks_passed"`
	Blocking     int `json:"blocking"`
	Warning      int `json:"warning"`
	Acknowledged int `json:"acknowledged"`
	Expired      int `json:"expired"`
	Ignored      int `json:"ignored"`
}

type CheckCategoryMap map[string][]category.RiskCategory

func NewFailedResult(source string, policyError string) *EvaluationResult {
	return &EvaluationResult{
		Status:   "FAILED",
		Source:   source,
		Error:    policyError,
		Policies: nil,
		Findings: []Finding{},
		Summary:  EvaluationSummary{},
	}
}

type storedPolicy struct {
	Policy  *CompiledPolicy `json:"policy"`
	RawYAML string          `json:"raw_yaml"`
	Error   string          `json:"error"`
}

type policyContext struct {
	strategy        PolicyStrategy
	repoCompiled    *CompiledPolicy
	repoYAML        string
	defaultCompiled *CompiledPolicy
	defaultYAML     string
	applied         *CompiledPolicy
}

func Evaluate(
	override *Policy,
	storedPolicyJSON string,
	policyDefault *Policy,
	v *violations.ViolationsResult,
	source string,
	evaluationTime time.Time,
	categoryMap CheckCategoryMap,
) (*EvaluationResult, error) {
	var overrideCompiled *CompiledPolicy
	var overrideYAML string
	if override != nil {
		var err error
		overrideCompiled, err = Compile(override)
		if err != nil {
			return nil, fmt.Errorf("compiling policy_override: %w", err)
		}
		overrideYAML, err = ToYAML(overrideCompiled)
		if err != nil {
			return nil, fmt.Errorf("serializing policy_override: %w", err)
		}
	}

	var defaultCompiled *CompiledPolicy
	var defaultYAML string
	if policyDefault != nil {
		var err error
		defaultCompiled, err = Compile(policyDefault)
		if err != nil {
			return nil, fmt.Errorf("compiling policy_default: %w", err)
		}
		defaultYAML, err = ToYAML(defaultCompiled)
		if err != nil {
			return nil, fmt.Errorf("serializing policy_default: %w", err)
		}
	} else {
		defaultCompiled = defaultPolicyClone()
		defaultYAML = DefaultPolicyYAML()
	}

	var repoPolicy *CompiledPolicy
	var repoYAML string
	var policyError string

	if storedPolicyJSON != "" {
		var sp storedPolicy
		if err := json.Unmarshal([]byte(storedPolicyJSON), &sp); err != nil {
			return nil, fmt.Errorf("parsing stored policy: %w", err)
		}
		repoPolicy = sp.Policy
		repoYAML = sp.RawYAML
		policyError = sp.Error
	}

	if policyError != "" {
		return NewFailedResult(source, policyError), nil
	}

	ctx := buildPolicyContext(overrideCompiled, overrideYAML, repoPolicy, repoYAML, defaultCompiled, defaultYAML)

	return EvaluateWithContext(ctx, v, source, evaluationTime, categoryMap)
}

func buildPolicyContext(
	overrideCompiled *CompiledPolicy,
	overrideYAML string,
	repoPolicy *CompiledPolicy,
	repoYAML string,
	defaultCompiled *CompiledPolicy,
	defaultYAML string,
) policyContext {
	if overrideCompiled != nil {
		marked := overrideCompiled.Clone()
		for i := range marked.Rules {
			marked.Rules[i].IsOverride = true
		}
		return policyContext{
			strategy:        PolicyStrategyOverride,
			repoCompiled:    repoPolicy,
			repoYAML:        repoYAML,
			defaultCompiled: defaultCompiled,
			defaultYAML:     defaultYAML,
			applied:         marked,
		}
	}

	if repoPolicy != nil {
		return policyContext{
			strategy:        PolicyStrategyMerged,
			repoCompiled:    repoPolicy,
			repoYAML:        repoYAML,
			defaultCompiled: defaultCompiled,
			defaultYAML:     defaultYAML,
			applied:         merge(defaultCompiled, repoPolicy),
		}
	}

	return policyContext{
		strategy:        PolicyStrategyDefaultOnly,
		repoCompiled:    nil,
		repoYAML:        "",
		defaultCompiled: defaultCompiled,
		defaultYAML:     defaultYAML,
		applied:         defaultCompiled,
	}
}

func EvaluateWithContext(
	ctx policyContext,
	v *violations.ViolationsResult,
	source string,
	evaluationTime time.Time,
	categoryMap CheckCategoryMap,
) (*EvaluationResult, error) {
	appliedYAML, err := ToYAML(ctx.applied)
	if err != nil {
		return nil, fmt.Errorf("serializing applied policy: %w", err)
	}

	breakdown := buildPolicyBreakdown(ctx, appliedYAML)
	return evaluateWithBreakdown(ctx.applied, breakdown, v, source, evaluationTime, categoryMap)
}

func buildPolicyBreakdown(ctx policyContext, appliedYAML string) *PolicyBreakdown {
	var repoSummary *PolicySummary
	if ctx.repoCompiled != nil {
		repoSummary = &PolicySummary{
			Version:   CurrentVersion,
			RuleCount: len(ctx.repoCompiled.Rules),
			RawYAML:   ctx.repoYAML,
		}
	}

	defaultSummary := &PolicySummary{
		Version:   CurrentVersion,
		RuleCount: len(ctx.defaultCompiled.Rules),
		RawYAML:   ctx.defaultYAML,
	}

	appliedRuleCount := 0
	if ctx.applied != nil {
		appliedRuleCount = len(ctx.applied.Rules)
	}

	appliedSummary := &PolicySummary{
		Version:   CurrentVersion,
		RuleCount: appliedRuleCount,
		RawYAML:   appliedYAML,
	}

	return &PolicyBreakdown{
		Strategy: ctx.strategy,
		Repo:     repoSummary,
		Default:  defaultSummary,
		Applied:  appliedSummary,
	}
}
