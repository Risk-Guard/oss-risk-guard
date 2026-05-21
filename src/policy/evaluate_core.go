package policy

import (
	"fmt"
	"risk-guard/src/violations"
	"time"
)

func evaluateWithBreakdown(
	policy *CompiledPolicy,
	breakdown *PolicyBreakdown,
	v *violations.ViolationsResult,
	source string,
	evaluationTime time.Time,
	categoryMap CheckCategoryMap,
) (*EvaluationResult, error) {
	workflowMode := WorkflowModeActive
	if policy != nil {
		if policy.Workflow != nil && policy.Workflow.Mode != "" {
			workflowMode = policy.Workflow.Mode
		}
	}

	result := &EvaluationResult{
		Source:       source,
		WorkflowMode: workflowMode,
		Policies:     breakdown,
		Findings:     []Finding{},
	}

	analysesWithBlocking := make(map[string]bool)
	summary := EvaluationSummary{TotalPackages: len(v.Analyses)}

	for _, analysis := range v.Analyses {
		ecosystem := extractEcosystem(analysis.AnalysisID)
		sourcePath := extractSourcePath(analysis.AnalysisID)
		depth := len(analysis.DependencyPath)

		for _, violation := range analysis.Violations {
			categories := categoryMap[violation.CheckCode]

			ctx := EvaluationContext{
				SourcePath:     sourcePath,
				Ecosystem:      ecosystem,
				Depth:          depth,
				Dev:            analysis.Dev,
				CheckCode:      violation.CheckCode,
				Categories:     categories,
				EvaluationTime: evaluationTime,
			}

			sevResult, err := policy.getSeverity(ctx)
			if err != nil {
				return nil, err
			}

			finding := Finding{
				Package:        analysis.AnalysisID,
				Check:          violation.CheckCode,
				Categories:     categoryStrings(categories),
				Rationale:      violation.Rationale,
				Evidence:       violation.Evidence,
				DependencyPath: analysis.DependencyPath,
				RootLocation:   analysis.RootLocation,
				Dev:            analysis.Dev,
				Note:           sevResult.Note,
				MatchedRule:    sevResult.MatchedRule,
			}

			if sevResult.ShouldIgnore() {
				finding.Kind = FindingIgnored
				result.Findings = append(result.Findings, finding)
				summary.Ignored++
				continue
			}

			if ack := policy.getExpectedFailure(analysis.AnalysisID, violation.CheckCode, depth); ack != nil {
				if ack.Expires != nil && ack.Expires.Before(evaluationTime) {
					finding.Kind = FindingExpired
					finding.Note = formatExpiredNote(ack)
					result.Findings = append(result.Findings, finding)
					summary.Expired++
					if sevResult.IsBlocking() {
						analysesWithBlocking[analysis.AnalysisID] = true
					}
				} else {
					finding.Kind = FindingAcknowledged
					finding.Note = formatAckNote(ack)
					result.Findings = append(result.Findings, finding)
					summary.Acknowledged++
				}
				continue
			}

			if sevResult.IsBlocking() {
				finding.Kind = FindingBlocking
				result.Findings = append(result.Findings, finding)
				summary.Blocking++
				analysesWithBlocking[analysis.AnalysisID] = true
			} else {
				finding.Kind = FindingWarning
				result.Findings = append(result.Findings, finding)
				summary.Warning++
			}
		}
	}

	if summary.Blocking > 0 || summary.Expired > 0 {
		result.Status = "BLOCKED"
	} else if summary.Warning > 0 {
		result.Status = "WARNING"
	} else {
		result.Status = "PASS"
	}

	count := len(v.Analyses) - len(analysesWithBlocking)
	summary.UnblockedPackages = count
	summary.ChecksPassed = count
	result.Summary = summary

	return result, nil
}

func EvaluateCompiled(
	policy *CompiledPolicy,
	v *violations.ViolationsResult,
	source string,
	evaluationTime time.Time,
	categoryMap CheckCategoryMap,
	rawYAML string,
) (*EvaluationResult, error) {
	appliedYAML, err := ToYAML(policy)
	if err != nil {
		return nil, fmt.Errorf("serializing policy: %w", err)
	}

	ruleCount := 0
	if policy != nil {
		ruleCount = len(policy.Rules)
	}

	breakdown := &PolicyBreakdown{
		Strategy: PolicyStrategyDefaultOnly,
		Repo:     nil,
		Default: &PolicySummary{
			Version:   CurrentVersion,
			RuleCount: ruleCount,
			RawYAML:   rawYAML,
		},
		Applied: &PolicySummary{
			Version:   CurrentVersion,
			RuleCount: ruleCount,
			RawYAML:   appliedYAML,
		},
	}

	return evaluateWithBreakdown(policy, breakdown, v, source, evaluationTime, categoryMap)
}
