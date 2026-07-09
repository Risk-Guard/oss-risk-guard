package package_detector_published

import (
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// SourceRef values record which tree DetectedManifests were scanned from, so
// provenance checks can disclose in their findings whether the comparison used
// the source as-published (gitHead) or fell back to current HEAD.
const (
	SourceRefGitHead = "gitHead" // detected at the published version's gitHead
	SourceRefHead    = "head"    // fell back to current default-branch HEAD
)

// Output mirrors package_detector.Output's DetectedManifests so provenance
// checks can consume it identically, but persists under its own key and leaves
// BaseOutput.Output nil: it never injects published-tree package names into the
// input flowing downstream.
type Output struct {
	dag_impl.BaseOutput
	DetectedManifests []models.ManifestResult `json:"detected_manifests"`
	// SourceRef is SourceRefGitHead or SourceRefHead; SourceCommit carries the
	// gitHead SHA when SourceRef == SourceRefGitHead.
	SourceRef    string `json:"source_ref,omitempty"`
	SourceCommit string `json:"source_commit,omitempty"`
}

func NewOutput(status executiondag.Status, statusReason string, manifests []models.ManifestResult, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput:        dag_impl.NewBaseOutput(status, statusReason, input),
		DetectedManifests: manifests,
	}
}

func (o *Output) PersistKey() string { return "packages_published" }

// GitHeadUsed reports whether DetectedManifests were scanned from the tree at
// the published version's gitHead; false means the scan fell back to the
// repository's current HEAD, which may have diverged from the published artifact.
func (o *Output) GitHeadUsed() bool { return o.SourceRef == SourceRefGitHead }
