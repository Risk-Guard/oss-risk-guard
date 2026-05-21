package policy

import (
	"fmt"
	"maps"
	"strings"

	"sigs.k8s.io/yaml"
)

func ToYAML(p *CompiledPolicy) (string, error) {
	if p == nil {
		return "", nil
	}

	policy := ToPolicy(p)
	data, err := yaml.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("marshaling policy to YAML: %w", err)
	}
	return string(data), nil
}

func ToPolicy(p *CompiledPolicy) *Policy {
	if p == nil {
		return nil
	}

	severity := make(map[string]SeverityValue)
	for _, rule := range p.Rules {
		path := severityPathToString(rule.Path)
		if _, exists := severity[path]; !exists {
			severity[path] = rule.Value
		}
	}

	expectedFailures := maps.Clone(p.ExpectedFailures)

	return &Policy{
		Version:          CurrentVersion,
		Workflow:         p.Workflow,
		Severity:         severity,
		ExpectedFailures: expectedFailures,
	}
}

func severityPathToString(path SeverityPath) string {
	var parts []string

	if path.SourcePath != nil {
		parts = append(parts, fmt.Sprintf("source/%q", *path.SourcePath))
	}

	if path.Ecosystem != nil {
		parts = append(parts, "ecosystem", *path.Ecosystem)
	}

	if path.DepthRange != nil {
		parts = append(parts, "depth", depthRangeToString(path.DepthRange))
	}

	if path.Env != nil {
		if *path.Env {
			parts = append(parts, "env", "dev")
		} else {
			parts = append(parts, "env", "prod")
		}
	}

	if path.Target.IsCategory {
		parts = append(parts, "category", path.Target.Name)
	} else {
		parts = append(parts, "check", path.Target.Name)
	}

	return strings.Join(parts, "/")
}

func depthRangeToString(r *DepthRange) string {
	if r.Min == r.Max {
		return fmt.Sprintf("%d", r.Min)
	}
	if r.Max == -1 {
		return fmt.Sprintf("%d+", r.Min)
	}
	return fmt.Sprintf("%d-%d", r.Min, r.Max)
}
