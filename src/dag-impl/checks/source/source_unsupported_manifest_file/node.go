package source_unsupported_manifest_file

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/unsupported_manifests"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "SOURCE_UNSUPPORTED_MANIFEST_FILE",
			Description: "Source repository uses package managers not currently supported for dependency parsing",
			Outcomes: storage.Outcomes{
				storage.StatusSkipped: "Only applicable to source analysis",
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategorySecurityVulnerability: "Other Risk Guard checks cannot be fully applied to ecosystems using unsupported package managers.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*unsupported_manifests.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	if !input.HasSourceKey() {
		return checks.NewSkippedOutput(n.Code, "Only applicable to source analysis", input), nil
	}

	unsupportedOut := executiondag.GetOutput[*unsupported_manifests.Node](ctx).(*unsupported_manifests.Output)

	if len(unsupportedOut.DetectedManifests) == 0 {
		return checks.NewCompliantOutput(n.Code, "No unsupported manifest files detected", input), nil
	}

	ecosystemCounts := make(map[string]int)
	for _, m := range unsupportedOut.DetectedManifests {
		ecosystemCounts[m.Ecosystem]++
	}

	var evidence []string
	for _, m := range unsupportedOut.DetectedManifests {
		if len(evidence) >= checks.MaxEvidenceItems {
			break
		}
		osvInfo := ""
		if m.OSVEcosystem != "" {
			osvInfo = fmt.Sprintf(", OSV ecosystem: %s", m.OSVEcosystem)
		}
		evidence = append(evidence, fmt.Sprintf("%s (%s%s)", m.RelPath, m.PackageManager, osvInfo))
	}

	rationale := fmt.Sprintf("Found %d unsupported manifest file(s) across %d ecosystem(s). Dependencies in these files are not parsed.",
		len(unsupportedOut.DetectedManifests), len(ecosystemCounts))

	return checks.NewViolationOutput(n.Code, rationale, evidence, input), nil
}
