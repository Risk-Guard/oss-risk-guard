package policy

import "sort"

func merge(base, overlay *CompiledPolicy) *CompiledPolicy {
	if overlay == nil {
		if base == nil {
			return nil
		}
		return base.Clone()
	}
	if base == nil {
		return overlay.Clone()
	}

	baseRules := make([]SeverityRule, len(base.Rules))
	for i, r := range base.Rules {
		c := r.clone()
		c.IsOverlay = false
		baseRules[i] = c
	}

	overlayRules := make([]SeverityRule, len(overlay.Rules))
	for i, r := range overlay.Rules {
		c := r.clone()
		c.IsOverlay = true
		overlayRules[i] = c
	}

	allRules := append(baseRules, overlayRules...)
	sort.SliceStable(allRules, func(i, j int) bool {
		if allRules[i].Specificity != allRules[j].Specificity {
			return allRules[i].Specificity > allRules[j].Specificity
		}
		if allRules[i].WildcardCount != allRules[j].WildcardCount {
			return allRules[i].WildcardCount < allRules[j].WildcardCount
		}
		if allRules[i].IsOverlay != allRules[j].IsOverlay {
			return allRules[i].IsOverlay
		}
		return false
	})

	expectedFailures := make(map[string]ExpectedFailureV2)
	for k, v := range base.ExpectedFailures {
		expectedFailures[k] = v.clone()
	}
	for k, v := range overlay.ExpectedFailures {
		expectedFailures[k] = v.clone()
	}

	expectedWarnings := make(map[string]ExpectedFailureV2)
	for k, v := range base.ExpectedWarnings {
		expectedWarnings[k] = v.clone()
	}
	for k, v := range overlay.ExpectedWarnings {
		expectedWarnings[k] = v.clone()
	}

	var workflow *WorkflowConfig
	if overlay.Workflow != nil {
		wf := *overlay.Workflow
		workflow = &wf
	} else if base.Workflow != nil {
		wf := *base.Workflow
		workflow = &wf
	}

	return &CompiledPolicy{
		Rules:            allRules,
		ExpectedFailures: expectedFailures,
		ExpectedWarnings: expectedWarnings,
		Workflow:         workflow,
	}
}
