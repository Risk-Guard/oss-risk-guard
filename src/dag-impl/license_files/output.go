package license_files

import (
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// Output is the output of the LicenseScannerNode.
// It contains the raw license-file candidates found on disk, before SPDX matching.
type Output struct {
	dag_impl.BaseOutput `json:",inline"`
	Files               []models.LicenseFile `json:"files"`
}

func NewOutput(status executiondag.Status, statusReason string, files []models.LicenseFile, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(status, statusReason, input),
		Files:      files,
	}
}

func (o *Output) PersistKey() string { return "license_files" }
