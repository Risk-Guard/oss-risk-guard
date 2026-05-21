package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func ValidatePattern(pattern string) error {
	if !strings.Contains(pattern, "*") {
		return nil
	}
	regexPattern := "^" + regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, `[^/]*`)
	regexPattern += "$"
	_, err := regexp.Compile(regexPattern)
	return err
}

func MatchesPattern(pattern, value string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	regexPattern := "^" + regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, `[^/]*`)
	regexPattern += "$"
	matched, _ := regexp.MatchString(regexPattern, value)
	return matched
}

type SeverityPath struct {
	SourcePath *string
	Ecosystem  *string
	DepthRange *DepthRange
	Env        *bool
	Target     PathTarget
}

type DepthRange struct {
	Min int
	Max int // -1 = infinity
}

func (r *DepthRange) Contains(depth int) bool {
	if depth < r.Min {
		return false
	}
	if r.Max != -1 && depth > r.Max {
		return false
	}
	return true
}

type PathTarget struct {
	IsCategory bool
	Name       string
}

var depthRangeRegex = regexp.MustCompile(`^(\d+)(\+|-(\d+))?$`)

func extractQuotedPath(path string, start int) (string, int, error) {
	if start >= len(path) || path[start] != '"' {
		return "", 0, fmt.Errorf("expected opening quote")
	}
	end := strings.Index(path[start+1:], `"`)
	if end == -1 {
		return "", 0, fmt.Errorf("unclosed quote")
	}
	quoted := path[start+1 : start+1+end]
	if quoted == "" {
		return "", 0, fmt.Errorf("empty quoted path")
	}
	return quoted, start + 1 + end + 1, nil
}

func ParseSeverityPath(path string) (*SeverityPath, error) {
	result := &SeverityPath{}
	remaining := path

	// Optional: source/"<pattern>"/
	if strings.HasPrefix(remaining, "source/") {
		remaining = remaining[7:] // skip "source/"
		if !strings.HasPrefix(remaining, `"`) {
			return nil, fmt.Errorf("source path must be quoted: source/\"path\"/..., got: %s", path)
		}
		sourcePath, endPos, err := extractQuotedPath(remaining, 0)
		if err != nil {
			return nil, fmt.Errorf("invalid quoted source path in %s: %w", path, err)
		}
		result.SourcePath = &sourcePath
		remaining = remaining[endPos:]
		if !strings.HasPrefix(remaining, "/") {
			return nil, fmt.Errorf("expected / after quoted source path in %s", path)
		}
		remaining = remaining[1:] // skip "/"
	}

	parts := strings.Split(remaining, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("path must have at least 2 segments: %s", path)
	}

	i, err := parseOptionalSegments(result, parts, path)
	if err != nil {
		return nil, err
	}

	i, err = parseTarget(result, parts, i, path)
	if err != nil {
		return nil, err
	}

	if i != len(parts) {
		return nil, fmt.Errorf("unexpected trailing segments in path %s", path)
	}

	return result, nil
}

func parseOptionalSegments(result *SeverityPath, parts []string, path string) (int, error) {
	i := 0

	if i < len(parts) && parts[i] == "ecosystem" {
		if i+1 >= len(parts) {
			return 0, fmt.Errorf("ecosystem requires a name: %s", path)
		}
		eco := parts[i+1]
		result.Ecosystem = &eco
		i += 2
	}

	if i < len(parts) && parts[i] == "depth" {
		if i+1 >= len(parts) {
			return 0, fmt.Errorf("depth requires a range: %s", path)
		}
		dr, err := parseDepthRange(parts[i+1])
		if err != nil {
			return 0, fmt.Errorf("invalid depth range %q in path %s: %w", parts[i+1], path, err)
		}
		result.DepthRange = dr
		i += 2
	}

	if i < len(parts) && parts[i] == "env" {
		if i+1 >= len(parts) {
			return 0, fmt.Errorf("env requires 'dev' or 'prod': %s", path)
		}
		env, err := parseEnvValue(parts[i+1], path)
		if err != nil {
			return 0, err
		}
		result.Env = env
		i += 2
	}

	return i, nil
}

func parseEnvValue(value, path string) (*bool, error) {
	switch value {
	case "dev":
		v := true
		return &v, nil
	case "prod":
		v := false
		return &v, nil
	default:
		return nil, fmt.Errorf("env must be 'dev' or 'prod', got %q in path %s", value, path)
	}
}

func parseTarget(result *SeverityPath, parts []string, i int, path string) (int, error) {
	if i >= len(parts) {
		return 0, fmt.Errorf("path missing target (category/... or check/...): %s", path)
	}

	switch parts[i] {
	case "category":
		if i+1 >= len(parts) {
			return 0, fmt.Errorf("category requires a name: %s", path)
		}
		result.Target = PathTarget{IsCategory: true, Name: parts[i+1]}
		return i + 2, nil
	case "check":
		if i+1 >= len(parts) {
			return 0, fmt.Errorf("check requires a code: %s", path)
		}
		result.Target = PathTarget{IsCategory: false, Name: parts[i+1]}
		return i + 2, nil
	default:
		return 0, fmt.Errorf("expected 'category' or 'check' but got %q in path %s", parts[i], path)
	}
}

func parseDepthRange(s string) (*DepthRange, error) {
	match := depthRangeRegex.FindStringSubmatch(s)
	if match == nil {
		return nil, fmt.Errorf("invalid depth range syntax")
	}

	min, err := strconv.Atoi(match[1])
	if err != nil {
		return nil, fmt.Errorf("invalid min value: %w", err)
	}

	if match[2] == "" {
		// Exact: "2" means depth == 2
		return &DepthRange{Min: min, Max: min}, nil
	}

	if match[2] == "+" {
		// Open-ended: "2+" means depth >= 2
		return &DepthRange{Min: min, Max: -1}, nil
	}

	// Range: "1-3" means 1 <= depth <= 3
	max, err := strconv.Atoi(match[3])
	if err != nil {
		return nil, fmt.Errorf("invalid max value: %w", err)
	}
	if max < min {
		return nil, fmt.Errorf("max %d < min %d", max, min)
	}
	return &DepthRange{Min: min, Max: max}, nil
}

func ParseExpectedFailurePath(path string) error {
	if path == "root" {
		return nil
	}
	if !strings.HasPrefix(path, "package/") && !strings.HasPrefix(path, "source/") {
		return fmt.Errorf("expected failure key must start with 'package/', 'source/', or be 'root': %s", path)
	}
	// Strip optional query string for validation
	clean := path
	if idx := strings.Index(clean, "?"); idx > 0 {
		clean = clean[:idx]
	}
	parts := strings.Split(clean, "/")
	if len(parts) < 3 {
		return fmt.Errorf("expected failure key must have at least 3 segments (e.g. package/npm/name): %s", path)
	}
	return nil
}

func ComputeSpecificity(path *SeverityPath) int {
	spec := 0
	if path.SourcePath != nil {
		spec += 2
	}
	if path.Ecosystem != nil {
		spec++
	}
	if path.DepthRange != nil {
		spec++
	}
	if path.Env != nil {
		spec++
	}
	if !path.Target.IsCategory {
		spec++
	}
	return spec
}

func CountWildcards(path *SeverityPath) int {
	count := 0
	if path.SourcePath != nil {
		count += strings.Count(*path.SourcePath, "*")
	}
	count += strings.Count(path.Target.Name, "*")
	return count
}
