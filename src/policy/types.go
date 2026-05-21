package policy

import (
	"encoding/json"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"time"
)

type Severity string

const (
	SeverityBlocking Severity = "blocking"
	SeverityWarning  Severity = "warning"
	SeverityIgnore   Severity = "ignore"
)

func (s Severity) Validate() error {
	if s != SeverityBlocking && s != SeverityWarning && s != SeverityIgnore {
		return fmt.Errorf("invalid severity %q: must be 'blocking', 'warning', or 'ignore'", s)
	}
	return nil
}

const CurrentVersion = 2

type WorkflowMode string

const (
	WorkflowModeActive   WorkflowMode = "active"
	WorkflowModeSilent   WorkflowMode = "silent"
	WorkflowModeDisabled WorkflowMode = "disabled"
)

type WorkflowConfig struct {
	Mode WorkflowMode `json:"mode" jsonschema:"enum=active,enum=silent,enum=disabled,default=active,description=Workflow mode: active (default) runs scan and posts GitHub checks; silent runs scan but skips GitHub check posting; disabled skips workflow entirely on push"`
}

type Policy struct {
	Version          int                          `json:"version" jsonschema:"enum=2,description=Policy file version (must be 2)"`
	Workflow         *WorkflowConfig              `json:"workflow,omitempty" jsonschema:"description=Workflow behavior configuration"`
	Severity         map[string]SeverityValue     `json:"severity,omitempty" jsonschema:"description=Severity rules mapping paths to severity levels. Path syntax: [source/pattern/][ecosystem/name/][depth/range/][env/dev|prod/](category/name | check/CODE). Supports * wildcard (matches within path segment). Source paths must be quoted. Examples: check/SOURCE_* or env/dev/category/critical or source/\"github.com/org/*\"/category/critical"`
	ExpectedFailures map[string]ExpectedFailureV2 `json:"expected_failures,omitempty" jsonschema:"description=Acknowledged violations keyed by package/ecosystem/name or source/host/org/repo or root. Each entry has a checks array listing check codes. Supports * wildcard and optional ?version=X.Y.Z. Examples: package/npm/lodash with checks: [VULN_CHECK] or root with checks: [SOURCE_NO_LICENSE]"`
	Overrides        map[string][]PolicyOverride  `json:"overrides,omitempty" jsonschema:"description=Package or source scoped output overrides keyed by package/ecosystem/name or source/host/org/repo. Values are arrays of path overrides."`
}

type PolicyOverride struct {
	Path   string `json:"path" jsonschema:"description=Dot-separated path to override (e.g. output.source_url)"`
	Value  any    `json:"value" jsonschema:"description=Value to set at the path"`
	Reason string `json:"reason" jsonschema:"description=E&O required: explanation for the override"`
}

type SeverityValue struct {
	Severity      Severity   `json:"severity" jsonschema:"enum=blocking,enum=warning,enum=ignore"`
	Reason        string     `json:"reason,omitempty"`
	BlockingAfter *time.Time `json:"blocking_after,omitempty" jsonschema:"description=Date after which severity escalates to blocking"`
}

func (v *SeverityValue) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		v.Severity = Severity(s)
		return nil
	}
	type raw SeverityValue
	return json.Unmarshal(data, (*raw)(v))
}

type ExpectedFailureV2 struct {
	Checks     []string   `json:"checks,omitempty" jsonschema:"description=Check codes to acknowledge for this entity"`
	Reason     string     `json:"reason" jsonschema:"description=Why this violation is acceptable"`
	Expires    *time.Time `json:"expires,omitempty" jsonschema:"description=Expiration date for acknowledgment"`
	ApprovedBy string     `json:"approved_by,omitempty" jsonschema:"description=Who approved this exception"`
}

// CompiledPolicy is the internal indexed representation. API clients should use Policy.
type CompiledPolicy struct {
	Rules            []SeverityRule
	ExpectedFailures map[string]ExpectedFailureV2
	Workflow         *WorkflowConfig
}

type SeverityRule struct {
	Path          SeverityPath
	Value         SeverityValue
	Specificity   int
	WildcardCount int
	IsOverlay     bool
	IsOverride    bool
}

type EvaluationContext struct {
	SourcePath     string
	Ecosystem      string
	Depth          int
	Dev            bool
	CheckCode      string
	Categories     []category.RiskCategory
	EvaluationTime time.Time
}

type SeverityResult struct {
	Severity    Severity
	Note        string
	MatchedRule string
}

func (s *SeverityResult) ShouldIgnore() bool {
	return s.Severity == SeverityIgnore
}

func (s *SeverityResult) IsBlocking() bool {
	return (s.Severity == SeverityBlocking)
}

func (p *CompiledPolicy) Clone() *CompiledPolicy {
	if p == nil {
		return nil
	}

	rules := make([]SeverityRule, len(p.Rules))
	for i, r := range p.Rules {
		rules[i] = r.clone()
	}

	expectedFailures := make(map[string]ExpectedFailureV2, len(p.ExpectedFailures))
	for k, v := range p.ExpectedFailures {
		expectedFailures[k] = v.clone()
	}

	var workflow *WorkflowConfig
	if p.Workflow != nil {
		wf := *p.Workflow
		workflow = &wf
	}

	return &CompiledPolicy{
		Rules:            rules,
		ExpectedFailures: expectedFailures,
		Workflow:         workflow,
	}
}

func (r SeverityRule) clone() SeverityRule {
	return SeverityRule{
		Path:          r.Path.clone(),
		Value:         r.Value.clone(),
		Specificity:   r.Specificity,
		WildcardCount: r.WildcardCount,
		IsOverlay:     r.IsOverlay,
		IsOverride:    r.IsOverride,
	}
}

func (p SeverityPath) clone() SeverityPath {
	c := SeverityPath{Target: p.Target}
	if p.SourcePath != nil {
		sp := *p.SourcePath
		c.SourcePath = &sp
	}
	if p.Ecosystem != nil {
		eco := *p.Ecosystem
		c.Ecosystem = &eco
	}
	if p.DepthRange != nil {
		dr := *p.DepthRange
		c.DepthRange = &dr
	}
	if p.Env != nil {
		env := *p.Env
		c.Env = &env
	}
	return c
}

func (v SeverityValue) clone() SeverityValue {
	c := SeverityValue{
		Severity: v.Severity,
		Reason:   v.Reason,
	}
	if v.BlockingAfter != nil {
		t := *v.BlockingAfter
		c.BlockingAfter = &t
	}
	return c
}

func (e ExpectedFailureV2) clone() ExpectedFailureV2 {
	c := ExpectedFailureV2{
		Reason:     e.Reason,
		ApprovedBy: e.ApprovedBy,
	}
	if len(e.Checks) > 0 {
		c.Checks = make([]string, len(e.Checks))
		copy(c.Checks, e.Checks)
	}
	if e.Expires != nil {
		t := *e.Expires
		c.Expires = &t
	}
	return c
}
