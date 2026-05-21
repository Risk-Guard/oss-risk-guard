package artifact_hash_mismatch

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/api/routes"
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/artifact_fetch"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "ARTIFACT_HASH_MISMATCH",
			Description: "Downloaded package artifact hash does not match registry-provided hash",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryCritical: "A hash mismatch means the artifact may have been tampered with or corrupted in transit, compromising supply chain integrity.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*artifact_fetch.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	artifactOut := executiondag.GetOutput[*artifact_fetch.Node](ctx).(*artifact_fetch.Output)

	if artifactOut.GetStatus() == executiondag.StatusSkipped {
		return checks.NewSkippedOutput(n.Code, artifactOut.GetStatusReason(), input), nil
	}

	return n.evaluate(artifactOut.Extractions, input), nil
}

func (n *Node) evaluate(extractions []routes.ArtifactExtraction, input dag_impl.Input) *checks.Output {
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

	if len(violations) > 0 {
		rationale := checks.BuildViolationRationale(violations, "failed hash verification", "failed hash verification")
		evidence := violations
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}
		return checks.NewViolationOutput(n.Code, rationale, evidence, input)
	}

	return checks.NewCompliantOutput(n.Code, "All artifacts verified"+checks.FormatScannedItems(scanned), input)
}
