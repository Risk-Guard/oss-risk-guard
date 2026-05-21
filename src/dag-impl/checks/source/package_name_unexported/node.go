package package_name_unexported

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"
	"strings"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "SOURCE_PACKAGE_NAME_UNEXPORTED",
			Description: "No package names detected in source code manifests",
			Categories: map[category.RiskCategory]string{
				category.RiskCategorySecurityVulnerability: "Without a declared package name, the published identity cannot be verified, enabling substitution or typosquatting.",
				category.RiskCategoryTitleAssurance:        "Source-to-package identity cannot be verified without an exported package name.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*package_detector.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	detectorOut := executiondag.GetOutput[*package_detector.Node](ctx).(*package_detector.Output)
	manifests := detectorOut.DetectedManifests

	var exported []string
	for _, m := range manifests {
		if m.Name == nil {
			continue
		}
		exported = append(exported, fmt.Sprintf("%s in %s", *m.Name, strings.Join(m.Paths, ", ")))
	}

	if len(exported) == 0 {
		log.Debug("SOURCE_PACKAGE_NAME_UNEXPORTED check: violation")
		return checks.NewViolationOutput(
			n.Code,
			"No package names exported in source code manifests",
			[]string{fmt.Sprintf("Found %d manifest(s) but none declare a package name", len(manifests))},
			input,
		), nil
	}

	log.Debug("SOURCE_PACKAGE_NAME_UNEXPORTED check: compliant",
		zap.Int("exported_count", len(exported)))
	return checks.NewCompliantOutput(
		n.Code,
		fmt.Sprintf("Found exported package name: %s", strings.Join(checks.TruncateEvidence(exported), "; ")),
		input,
	), nil
}
