package provenance_verify

import (
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
	"github.com/Risk-Guard/oss-risk-guard/src/provenance"
)

// Output records the outcome of verifying a package version's build provenance.
// Verified is true only when the attestation cryptographically verified AND its
// attested source repo matches the analyzed repo. FailReason distinguishes the
// failure modes for consuming checks (see provenance.FailReason).
//
// This node always reports StatusSuccess (even "no attestation") so that adding it
// as a dependency never auto-skips the checks that read it — the DAG auto-skips a
// node when any dependency is StatusSkipped.
type Output struct {
	dag_impl.BaseOutput
	Verified   bool   `json:"verified"`
	SourceRepo string `json:"source_repo,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Commit     string `json:"commit,omitempty"`
	FailReason string `json:"fail_reason,omitempty"`
}

func NewOutput(status executiondag.Status, statusReason string, res provenance.Result, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(status, statusReason, input),
		Verified:   res.Verified,
		SourceRepo: res.SourceRepo,
		Ref:        res.Ref,
		Commit:     res.Commit,
		FailReason: string(res.FailReason),
	}
}

func (o *Output) PersistKey() string { return "provenance_verify" }
