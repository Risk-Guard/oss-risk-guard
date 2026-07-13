package package_invalid_artifact

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/artifact"
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/artifact_fetch"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/provenance_verify"
	"github.com/Risk-Guard/oss-risk-guard/src/provenance"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "PACKAGE_INVALID_ARTIFACT",
			Description: "Published package artifact fails hash or build-provenance verification",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryCritical: "A failed artifact hash or build-provenance check means the artifact may have been tampered with, compromising supply chain integrity.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*artifact_fetch.Node](),
		executiondag.DependsOn[*provenance_verify.Node](),
	}
}

// AllowAutoSkip returns false so this check still runs when artifact_fetch skips —
// an advertised-but-failed provenance attestation must still be surfaced even
// when the tarball itself wasn't fetched for hashing.
func (n *Node) AllowAutoSkip() bool { return false }

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	artifactOut := executiondag.GetOutput[*artifact_fetch.Node](ctx).(*artifact_fetch.Output)
	provOut := executiondag.GetOutput[*provenance_verify.Node](ctx).(*provenance_verify.Output)
	provViolation := provenanceArtifactViolation(provOut)

	if artifactOut.GetStatus() == executiondag.StatusSkipped {
		// Even when the tarball wasn't fetched for hashing, an advertised provenance
		// that fails to verify is a tampering signal worth surfacing on its own.
		if provViolation != "" {
			return checks.NewViolationOutput(n.Code, "package artifact failed provenance verification", []string{provViolation}, input), nil
		}
		return checks.NewSkippedOutput(n.Code, artifactOut.GetStatusReason(), input), nil
	}

	return n.evaluate(artifactOut.Extractions, provViolation, input), nil
}

// provenanceArtifactViolation reports an artifact-integrity violation derived from
// build provenance: a bad signature or a subject digest that does not match the
// published artifact. A repo mismatch is deliberately NOT handled here — that
// artifact is validly signed and belongs to PACKAGE_SOURCE_URL_MISMATCH.
func provenanceArtifactViolation(o *provenance_verify.Output) string {
	switch o.FailReason {
	case string(provenance.FailInvalidSignature):
		return "Build provenance attestation failed signature verification (possible tampering)"
	case string(provenance.FailDigestMismatch):
		return "Build provenance attests a different artifact digest than the published package"
	default:
		return ""
	}
}

func (n *Node) evaluate(extractions []artifact.ArtifactExtraction, provViolation string, input dag_impl.Input) *checks.Output {
	var violations []string
	var scanned []string

	for _, extraction := range extractions {
		if extraction.SkipReason != nil {
			continue
		}

		scanned = append(scanned, fmt.Sprintf("%s/%s", extraction.Ecosystem, extraction.PackageName))

		if !extraction.Verified && extraction.VerifyError != nil {
			evidence := fmt.Sprintf(
				"%s/%s: %s (URL: %s)",
				extraction.Ecosystem,
				extraction.PackageName,
				*extraction.VerifyError,
				extraction.ArtifactURL,
			)
			violations = append(violations, evidence)
		}
	}

	if provViolation != "" {
		violations = append(violations, provViolation)
	}

	if len(violations) > 0 {
		rationale := checks.BuildViolationRationale(violations, "failed integrity verification", "failed integrity verification")
		evidence := violations
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}
		return checks.NewViolationOutput(n.Code, rationale, evidence, input)
	}

	return checks.NewCompliantOutput(n.Code, "All artifacts verified"+checks.FormatScannedItems(scanned), input)
}
