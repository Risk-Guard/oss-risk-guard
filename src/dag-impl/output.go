package dag_impl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"risk-guard/src/runpath"

	executiondag "risk-guard/src/execution-dag"

	"sigs.k8s.io/yaml"
)

// Compile-time check that BaseOutput implements MergeableOutput
var _ MergeableOutput = (*BaseOutput)(nil)

// BaseOutput provides common fields and methods for all dag-impl outputs.
// It embeds executiondag.BaseOutput for status management and implements
// MergeableOutput for Input.Merge() operations.
//
// All dag-impl outputs should embed this type.
type BaseOutput struct {
	executiondag.BaseOutput `json:",inline"`

	Input  Input  `json:"-"`
	Output *Input `json:"output,omitempty"`
}

func NewBaseOutput(status executiondag.Status, statusReason string, input Input) BaseOutput {
	return BaseOutput{
		BaseOutput: executiondag.BaseOutput{
			Status:       status,
			StatusReason: statusReason,
		},
		Input:  input,
		Output: nil,
	}
}

func (b *BaseOutput) GetInput() *Input {
	return &b.Input
}

func (b *BaseOutput) GetOutput() *Input {
	return b.Output
}

// ReadYAML reads and unmarshals YAML data from a file at the specified path.
func ReadYAML(path string, target any) error {
	//nolint:gosec // Path is constructed from validated output directory
	yamlData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(yamlData, target); err != nil {
		return fmt.Errorf("unmarshaling YAML: %w", err)
	}

	return nil
}

func ReadOutput[T executiondag.Persistable](ctx context.Context, input Input) (T, error) {
	var zero T
	key := zero.PersistKey()
	inputDir := runpath.GetInputDir(ctx)
	filePath := filepath.Join(inputDir, input.BasePath(), key+".yml")

	var result T
	if err := ReadYAML(filePath, &result); err != nil {
		return zero, fmt.Errorf("reading cached %s: %w", key, err)
	}

	return result, nil
}
