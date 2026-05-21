package version_transformer

import (
	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
	"risk-guard/src/models"
)

// VersionOutput represents the transformed version metadata for a single package.
type VersionOutput struct {
	Ecosystem string                  `json:"ecosystem"`
	Name      string                  `json:"name"`
	Metadata  *models.VersionMetadata `json:"metadata"`
}

// Output is the output of the VersionTransformerNode.
// It contains the status and parsed version metadata for all transformed packages.
type Output struct {
	dag_impl.BaseOutput `json:",inline"`

	// Outputs contains the transformed version metadata for each package.
	Outputs []VersionOutput `json:"outputs"`
}

func NewOutput(status executiondag.Status, statusReason string, outputs []VersionOutput, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(status, statusReason, input),
		Outputs:    outputs,
	}
}

func (o *Output) GetVersionMetadata(ecosystem, name string) *models.VersionMetadata {
	for _, output := range o.Outputs {
		if output.Ecosystem == ecosystem && output.Name == name {
			return output.Metadata
		}
	}
	return nil
}

func (o *Output) PersistKey() string { return "version-metadata" }
