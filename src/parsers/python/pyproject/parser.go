package pyproject

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/parsers/python/pep508"

	"github.com/BurntSushi/toml"

	pythonnormalize "github.com/Risk-Guard/oss-risk-guard/src/language/python/normalize"
)

type PyProjectToml struct {
	Project *Project `toml:"project"`
	Tool    *Tool    `toml:"tool"`
}

type Project struct {
	Name         string   `toml:"name"`
	Dynamic      []string `toml:"dynamic"`
	Dependencies []string `toml:"dependencies"`
}

type NameResult struct {
	Name          *string
	IsDynamic     bool
	DynamicReason string
}

func (nr NameResult) GetName() *string         { return nr.Name }
func (nr NameResult) GetIsDynamic() bool       { return nr.IsDynamic }
func (nr NameResult) GetDynamicReason() string { return nr.DynamicReason }

func ParseName(content string) NameResult {
	var pyproject PyProjectToml

	if err := toml.Unmarshal([]byte(content), &pyproject); err != nil {
		return NameResult{}
	}

	if pyproject.Project != nil {
		if slices.Contains(pyproject.Project.Dynamic, "name") {
			return NameResult{
				IsDynamic:     true,
				DynamicReason: "name is listed in [project.dynamic]",
			}
		}

		if pyproject.Project.Name != "" {
			name := pyproject.Project.Name
			return NameResult{Name: &name}
		}
	}

	if pyproject.Tool != nil && pyproject.Tool.Flit != nil && pyproject.Tool.Flit.Metadata != nil {
		fm := pyproject.Tool.Flit.Metadata
		if fm.DistName != "" {
			name := fm.DistName
			return NameResult{Name: &name}
		}
		if fm.Module != "" {
			name := fm.Module
			return NameResult{Name: &name}
		}
	}

	return NameResult{}
}

type Tool struct {
	Poetry *Poetry `toml:"poetry"`
	Flit   *Flit   `toml:"flit"`
}

type Flit struct {
	Metadata *FlitMetadata `toml:"metadata"`
}

type FlitMetadata struct {
	Module   string `toml:"module"`
	DistName string `toml:"dist-name"`
}

type Poetry struct {
	Dependencies    map[string]any `toml:"dependencies"`
	DevDependencies map[string]any `toml:"dev-dependencies"`
}

func Parse(content string, sourceFile string) ([]models.Dependency, error) {
	var pyproject PyProjectToml

	if err := toml.Unmarshal([]byte(content), &pyproject); err != nil {
		return nil, fmt.Errorf("failed to parse pyproject.toml: %w", err)
	}

	var deps []models.Dependency

	if pyproject.Project != nil && pyproject.Project.Dependencies != nil {
		for _, depStr := range pyproject.Project.Dependencies {
			dep := pep508.ParseRequirementLine(depStr, sourceFile)
			if dep != nil {
				if dep.Location == nil {
					dep.Location = &models.LocationInfo{}
				}
				dep.Location.LineNumber = findLineNumber(content, dep.GetName())
				deps = append(deps, *dep)
			}
		}
	}

	if pyproject.Tool != nil && pyproject.Tool.Poetry != nil {
		deps = append(deps, parsePoetryDependencies(pyproject.Tool.Poetry.Dependencies, sourceFile, content, false)...)
		deps = append(deps, parsePoetryDependencies(pyproject.Tool.Poetry.DevDependencies, sourceFile, content, true)...)
	}

	return deps, nil
}

func parsePoetryDependencies(poetryDeps map[string]any, sourceFile string, content string, dev bool) []models.Dependency {
	var deps []models.Dependency

	for name, constraint := range poetryDeps {
		if name == "python" {
			continue
		}

		constraintStr, ok := constraint.(string)
		if !ok {
			continue
		}

		deps = append(deps, models.Dependency{
			AnalysisIdentifier: models.MakeSimplePackageAnalysisIdentifier("pypi", pythonnormalize.NormalizePyPIName(name)),
			Specifiers:         []string{constraintStr},
			Dev:                dev,
			Location: &models.LocationInfo{
				File:       &sourceFile,
				LineNumber: findLineNumber(content, name),
			},
		})
	}

	return deps
}

func findLineNumber(content string, packageName string) *int {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, packageName) {
			lineNum := i + 1
			return &lineNum
		}
	}
	return nil
}
