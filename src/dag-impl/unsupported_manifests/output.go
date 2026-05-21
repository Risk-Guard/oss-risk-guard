package unsupported_manifests

import (
	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
	"risk-guard/src/language/unsupported"
)

type Output struct {
	dag_impl.BaseOutput `json:",inline"`
	DetectedManifests   []unsupported.DetectedManifest `json:"detected_manifests"`
}

func NewOutput(status executiondag.Status, statusReason string, manifests []unsupported.DetectedManifest, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput:        dag_impl.NewBaseOutput(status, statusReason, input),
		DetectedManifests: manifests,
	}
}

func (o *Output) PersistKey() string {
	return "unsupported-manifests"
}
