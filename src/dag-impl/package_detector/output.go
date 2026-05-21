package package_detector

import (
	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
	"risk-guard/src/models"
)

type Output struct {
	dag_impl.BaseOutput `json:",inline"`
	DetectedManifests   []models.ManifestResult `json:"detected_manifests"`
}

func NewOutput(status executiondag.Status, statusReason string, manifests []models.ManifestResult, input dag_impl.Input) *Output {
	baseOutput := dag_impl.NewBaseOutput(status, statusReason, input)

	returnValue := func() *Output {
		return &Output{
			BaseOutput:        baseOutput,
			DetectedManifests: manifests,
		}
	}
	if len(manifests) == 0 {
		return returnValue()
	}
	// This dag was triggered by a packages so package => source => package does not make sense
	if !input.HasSourceKey() {
		return returnValue()
	}

	seen := make(map[string]bool)
	var packages []models.PackageInfo
	for _, m := range manifests {
		if m.Name == nil {
			continue
		}
		key := m.Ecosystem + "/" + *m.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		packages = append(packages, models.PackageInfo{
			Ecosystem: m.Ecosystem,
			Name:      *m.Name,
			Private:   m.Private,
		})
	}
	baseOutput.Output = &dag_impl.Input{
		SourceURL: input.SourceURL,
		Packages:  packages,
	}

	return returnValue()
}

func (o *Output) PersistKey() string { return "packages" }

func (o *Output) GetParseErrors() []models.ParseError {
	var errors []models.ParseError
	for _, m := range o.DetectedManifests {
		if m.ParseError != nil {
			errors = append(errors, models.ParseError{
				FilePath: m.Paths[0],
				Error:    *m.ParseError,
			})
		}
	}
	return errors
}

func (o *Output) GetAllDependencies() []models.Dependency {
	var deps []models.Dependency
	for _, m := range o.DetectedManifests {
		deps = append(deps, m.Dependencies...)
	}
	return deps
}

func (o *Output) GetAllLockfileDependencies() []models.DepsTreeEdge {
	var edges []models.DepsTreeEdge
	for _, m := range o.DetectedManifests {
		edges = append(edges, m.LockfileDependencies...)
	}
	return edges
}
