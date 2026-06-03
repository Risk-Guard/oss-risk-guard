package policy

import (
	"fmt"
	"strings"
	"time"
)

func (p *CompiledPolicy) getSeverity(ctx EvaluationContext) (SeverityResult, error) {
	if p == nil {
		p = defaultPolicyClone()
	}

	var bestRule *SeverityRule
	var bestResult *SeverityResult
	for i := range p.Rules {
		rule := &p.Rules[i]
		if !rule.Matches(ctx) {
			continue
		}
		resolved := rule.Resolve(ctx.EvaluationTime)
		if bestRule == nil {
			bestRule = rule
			bestResult = &resolved
			continue
		}
		if rule.Specificity > bestRule.Specificity {
			bestRule = rule
			bestResult = &resolved
		} else if rule.Specificity == bestRule.Specificity && severityRank(resolved.Severity) > severityRank(bestResult.Severity) {
			bestRule = rule
			bestResult = &resolved
		}
	}

	if bestResult != nil {
		bestResult.MatchedRule = formatMatchedRule(bestRule, bestResult.Severity)
		return *bestResult, nil
	}

	if len(ctx.Categories) == 0 {
		return SeverityResult{}, fmt.Errorf("check %q has no category defined", ctx.CheckCode)
	}
	return SeverityResult{Severity: SeverityBlocking}, nil
}

func formatMatchedRule(rule *SeverityRule, resolved Severity) string {
	path := severityPathToString(rule.Path)

	var source string
	switch {
	case rule.IsOverride:
		source = "override"
	case rule.IsOverlay:
		source = "repo"
	default:
		source = "default"
	}

	return fmt.Sprintf("%s: %s (%s)", path, resolved, source)
}

func severityRank(s Severity) int {
	switch s {
	case SeverityBlocking:
		return 2
	case SeverityWarning:
		return 1
	case SeverityIgnore:
		return 0
	default:
		return -1
	}
}

func entitySpecificity(pattern string) int {
	if pattern == "root" {
		return 0
	}
	spec := 0
	if strings.Contains(pattern, "?") {
		spec += 2
	}
	if !strings.Contains(pattern, "*") {
		spec++
	}
	return spec
}

func checksContain(checks []string, checkCode string) bool {
	for _, c := range checks {
		if MatchesPattern(c, checkCode) {
			return true
		}
	}
	return false
}

func (p *CompiledPolicy) getExpectedFailure(entityKey, checkCode string, depth int) *ExpectedFailureV2 {
	if p == nil {
		return nil
	}
	return matchAck(p.ExpectedFailures, entityKey, checkCode, depth)
}

// getExpectedWarning resolves an expected_warnings acknowledgment for a finding.
// It uses the same entity/check matching as expected_failures but reads the
// separate expected_warnings table. Callers only consult it for warning-level
// findings, so it can never silence a blocking finding.
func (p *CompiledPolicy) getExpectedWarning(entityKey, checkCode string, depth int) *ExpectedFailureV2 {
	if p == nil {
		return nil
	}
	return matchAck(p.ExpectedWarnings, entityKey, checkCode, depth)
}

// matchAck finds the most specific acknowledgment in table whose key pattern
// matches entityKey and whose checks include checkCode. "root" entries match
// only at depth 0. Shared by expected_failures and expected_warnings.
func matchAck(table map[string]ExpectedFailureV2, entityKey, checkCode string, depth int) *ExpectedFailureV2 {
	var bestPattern string
	var bestEF *ExpectedFailureV2
	bestSpec := -1
	for pattern, ef := range table {
		if pattern == "root" {
			continue
		}
		matchEntity := entityKey
		if !strings.Contains(pattern, "?") {
			matchEntity = stripQuery(matchEntity)
		}
		if !MatchesPattern(pattern, matchEntity) {
			continue
		}
		if !checksContain(ef.Checks, checkCode) {
			continue
		}
		spec := entitySpecificity(pattern)
		if spec > bestSpec || (spec == bestSpec && len(pattern) > len(bestPattern)) {
			bestSpec = spec
			efCopy := ef
			bestEF = &efCopy
			bestPattern = pattern
		}
	}
	if bestEF != nil {
		return bestEF
	}
	if depth == 0 {
		if ef, ok := table["root"]; ok {
			if checksContain(ef.Checks, checkCode) {
				efCopy := ef
				bestEF = &efCopy
				_ = bestPattern
			}
		}
	}
	return bestEF
}

func (r *SeverityRule) Matches(ctx EvaluationContext) bool {
	if r.Path.SourcePath != nil && !MatchesPattern(*r.Path.SourcePath, ctx.SourcePath) {
		return false
	}
	if r.Path.Ecosystem != nil && !MatchesPattern(*r.Path.Ecosystem, ctx.Ecosystem) {
		return false
	}
	if r.Path.DepthRange != nil && !r.Path.DepthRange.Contains(ctx.Depth) {
		return false
	}
	if r.Path.Env != nil && *r.Path.Env != ctx.Dev {
		return false
	}
	if r.Path.Target.IsCategory {
		for _, cat := range ctx.Categories {
			if MatchesPattern(r.Path.Target.Name, string(cat)) {
				return true
			}
		}
		return false
	}
	return MatchesPattern(r.Path.Target.Name, ctx.CheckCode)
}

func (r *SeverityRule) Resolve(evalTime time.Time) SeverityResult {
	if r.Value.BlockingAfter != nil {
		dateStr := r.Value.BlockingAfter.Format("2006-01-02")
		if evalTime.After(*r.Value.BlockingAfter) {
			return SeverityResult{
				Severity: SeverityBlocking,
				Note:     fmt.Sprintf("Severity bumped from %s to blocking after %s", r.Value.Severity, dateStr),
			}
		}
		return SeverityResult{
			Severity: r.Value.Severity,
			Note:     fmt.Sprintf("Will become blocking after %s", dateStr),
		}
	}
	result := SeverityResult{Severity: r.Value.Severity}
	if r.Value.Reason != "" {
		result.Note = r.Value.Reason
	}
	return result
}
