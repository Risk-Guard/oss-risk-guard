package policy

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

//go:embed default_policy.yml
var defaultPolicyYAML []byte

var defaultPolicy *CompiledPolicy

func init() {
	p, err := LoadFromBytes(defaultPolicyYAML, "default_policy.yml")
	if err != nil {
		panic(fmt.Sprintf("failed to load default policy: %v", err))
	}
	defaultPolicy = p
}

func defaultPolicyClone() *CompiledPolicy {
	return defaultPolicy.Clone()
}

func DefaultPolicy() *CompiledPolicy {
	return defaultPolicy.Clone()
}

func DefaultPolicyYAML() string {
	return string(defaultPolicyYAML)
}

const PolicyFileName = ".risk-guard.yml"

type LoadResult struct {
	Policy    *CompiledPolicy
	Overrides map[string][]PolicyOverride
}

func LoadFromBytes(data []byte, source string) (*CompiledPolicy, error) {
	result, err := LoadFullFromBytes(data, source)
	if err != nil {
		return nil, err
	}
	return result.Policy, nil
}

func LoadFullFromBytes(data []byte, source string) (*LoadResult, error) {
	var v struct {
		Version int `json:"version"`
	}
	if err := yaml.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", source, err)
	}
	if v.Version == 0 {
		return nil, fmt.Errorf("%s: version field is required", source)
	}
	if v.Version != CurrentVersion {
		return nil, fmt.Errorf("%s: unsupported version %d (current: %d)", source, v.Version, CurrentVersion)
	}

	var cfg Policy
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", source, err)
	}

	compiled, err := Compile(&cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}

	if err := validateOverrides(cfg.Overrides, source); err != nil {
		return nil, err
	}

	return &LoadResult{Policy: compiled, Overrides: cfg.Overrides}, nil
}

func Compile(p *Policy) (*CompiledPolicy, error) {
	if p == nil {
		return nil, nil
	}

	if p.Version != 0 && p.Version != CurrentVersion {
		return nil, fmt.Errorf("unsupported version %d (current: %d)", p.Version, CurrentVersion)
	}

	rules, err := parseSeverityRules(p.Severity)
	if err != nil {
		return nil, err
	}

	expectedFailures := make(map[string]ExpectedFailureV2)
	for path, ef := range p.ExpectedFailures {
		if err := ParseExpectedFailurePath(path); err != nil {
			return nil, fmt.Errorf("expected_failures: %w", err)
		}
		if len(ef.Checks) == 0 {
			return nil, fmt.Errorf("expected_failures %q: checks array is required", path)
		}
		if err := ValidatePattern(path); err != nil {
			return nil, fmt.Errorf("expected_failures %q: invalid pattern: %w", path, err)
		}
		for _, check := range ef.Checks {
			if err := ValidatePattern(check); err != nil {
				return nil, fmt.Errorf("expected_failures %q check %q: invalid pattern: %w", path, check, err)
			}
		}
		expectedFailures[path] = ef
	}

	return &CompiledPolicy{
		Rules:            rules,
		ExpectedFailures: expectedFailures,
		Workflow:         p.Workflow,
	}, nil
}

func parseSeverityRules(severity map[string]SeverityValue) ([]SeverityRule, error) {
	var rules []SeverityRule
	for path, value := range severity {
		parsed, err := ParseSeverityPath(path)
		if err != nil {
			return nil, fmt.Errorf("severity path %q: %w", path, err)
		}

		if err := value.Severity.Validate(); err != nil {
			return nil, fmt.Errorf("severity %q: %w", path, err)
		}

		if err := ValidatePattern(parsed.Target.Name); err != nil {
			return nil, fmt.Errorf("severity path %q: invalid pattern in target: %w", path, err)
		}
		if parsed.SourcePath != nil {
			if err := ValidatePattern(*parsed.SourcePath); err != nil {
				return nil, fmt.Errorf("severity path %q: invalid pattern in source path: %w", path, err)
			}
		}

		rules = append(rules, SeverityRule{
			Path:          *parsed,
			Value:         value,
			Specificity:   ComputeSpecificity(parsed),
			WildcardCount: CountWildcards(parsed),
		})
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Specificity != rules[j].Specificity {
			return rules[i].Specificity > rules[j].Specificity
		}
		if rules[i].WildcardCount != rules[j].WildcardCount {
			return rules[i].WildcardCount < rules[j].WildcardCount
		}
		iName := rules[i].Path.Target.Name
		jName := rules[j].Path.Target.Name
		if len(iName) != len(jName) {
			return len(iName) > len(jName)
		}
		return iName < jName
	})

	return rules, nil
}

func validateOverrides(overrides map[string][]PolicyOverride, source string) error {
	for key, items := range overrides {
		if !hasValidOverrideKeyPrefix(key) {
			return fmt.Errorf("%s: override key %q must start with 'package/' or 'source/'", source, key)
		}
		for i, override := range items {
			if override.Path == "" {
				return fmt.Errorf("%s: override %q[%d]: path is required", source, key, i)
			}
			if override.Reason == "" {
				return fmt.Errorf("%s: override %q[%d]: reason is required (E&O compliance)", source, key, i)
			}
		}
	}
	return nil
}

func hasValidOverrideKeyPrefix(key string) bool {
	return strings.HasPrefix(key, "package/") || strings.HasPrefix(key, "source/")
}
