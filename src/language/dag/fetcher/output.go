package fetcher

import (
	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
	"risk-guard/src/language"
)

// RegistryOutput represents the registry response for a single package.
type RegistryOutput struct {
	Ecosystem string                     `json:"ecosystem"`
	Name      string                     `json:"name"`
	Response  *language.RegistryResponse `json:"response"`
}

// Output is the output of the FetcherNode.
// It contains the status and registry responses for all fetched packages.
type Output struct {
	dag_impl.BaseOutput `json:",inline"`

	// Outputs contains the registry output for each fetched package.
	Outputs []RegistryOutput `json:"outputs"`
}

func NewOutput(status executiondag.Status, statusReason string, outputs []RegistryOutput, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(status, statusReason, input),
		Outputs:    outputs,
	}
}

func (o *Output) GetRegistryResponse(ecosystem, name string) *language.RegistryResponse {
	for _, output := range o.Outputs {
		if output.Ecosystem == ecosystem && output.Name == name {
			return output.Response
		}
	}
	return nil
}

func (o *Output) PersistKey() string { return "registry" }
