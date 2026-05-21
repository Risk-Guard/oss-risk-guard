package artifact_fetch

import (
	"github.com/Risk-Guard/oss-risk-guard/src/api/routes"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// Output is the output of the artifact_fetch node.
type Output struct {
	dag_impl.BaseOutput `json:",inline"`
	Extractions         []routes.ArtifactExtraction `json:"extractions"`
}

func NewOutput(status executiondag.Status, statusReason string, extractions []routes.ArtifactExtraction, input dag_impl.Input) *Output {
	baseOutput := dag_impl.NewBaseOutput(status, statusReason, input)
	return &Output{
		BaseOutput:  baseOutput,
		Extractions: extractions,
	}
}

func (o *Output) PersistKey() string { return "artifact" }

func (o *Output) GetExtraction(ecosystem, packageName string) *routes.ArtifactExtraction {
	for i := range o.Extractions {
		if o.Extractions[i].Ecosystem == ecosystem && o.Extractions[i].PackageName == packageName {
			return &o.Extractions[i]
		}
	}
	return nil
}
