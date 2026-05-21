package python

import (
	"fmt"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/parsers/python/pep508"
)

func (p *Python) parseDependencies(requiresDist []string) ([]models.Dependency, error) {
	if len(requiresDist) == 0 {
		return []models.Dependency{}, nil
	}
	deps := make([]models.Dependency, 0, len(requiresDist))
	for _, req := range requiresDist {
		dep, err := p.parseDependency(req)
		if err != nil {
			return nil, err
		}
		if dep != nil {
			deps = append(deps, *dep)
		}
	}
	return deps, nil
}

func (p *Python) parseDependency(req string) (*models.Dependency, error) {
	parts := strings.Split(req, ";")
	packagePart := strings.TrimSpace(parts[0])
	var environmentMarker *string
	var extraMarker *string
	if len(parts) > 1 {
		marker := strings.TrimSpace(parts[1])
		environmentMarker = &marker
		extraMarker = extractExtraMarker(marker)
	}
	result := pep508.Parse(packagePart)
	name := result.Name
	if name == "" {
		if result.ParseError == "" {
			return nil, nil
		}
		return nil, fmt.Errorf("pypi dependency has empty name: %q", req)
	}
	var extras []string
	if idx := strings.Index(name, "["); idx != -1 {
		extrasStr := name[idx+1:]
		if endIdx := strings.Index(extrasStr, "]"); endIdx != -1 {
			extrasStr = extrasStr[:endIdx]
			extras = strings.Split(extrasStr, ",")
			for i := range extras {
				extras[i] = strings.TrimSpace(extras[i])
			}
		}
		name = name[:idx]
	}

	var parseError *string
	if result.ParseError != "" {
		parseError = &result.ParseError
	}

	return &models.Dependency{
		AnalysisIdentifier: models.MakeSimplePackageAnalysisIdentifier("pypi", name),
		Specifiers:         result.Specifiers,
		EnvironmentMarker:  environmentMarker,
		Extras:             extras,
		ExtraMarker:        extraMarker,
		ParseError:         parseError,
	}, nil
}
