package package_dynamic_name

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"

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
			Code:        "PACKAGE_DYNAMIC_NAME",
			Description: "Package name in source code is determined dynamically",
			Categories: map[category.RiskCategory]string{
				category.RiskCategorySecurityVulnerability: "A dynamically computed package name can disguise which package is actually published, enabling substitution or typosquatting attacks.",
				category.RiskCategoryTitleAssurance:        "Source-to-package identity cannot be verified when the name is computed at build time.",
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

	if len(manifests) == 0 {
		log.Debug("PACKAGE_DYNAMIC_NAME check: skipped - no package definitions found")
		return checks.NewSkippedOutput(
			n.Code,
			"No package definitions found in source code",
			input,
		), nil
	}

	var dynamicPackages []string
	var dynamicReasons []string

	for _, manifest := range manifests {
		if manifest.IsDynamic {
			sourceFile := manifest.Paths[0]
			dynamicPackages = append(dynamicPackages, sourceFile)
			if manifest.DynamicReason != nil {
				dynamicReasons = append(dynamicReasons, fmt.Sprintf("%s: %s", sourceFile, *manifest.DynamicReason))
			} else {
				dynamicReasons = append(dynamicReasons, fmt.Sprintf("%s: reason not available", sourceFile))
			}
		}
	}

	if len(dynamicPackages) > 0 {
		rationale := checks.BuildViolationRationale(dynamicReasons, "has a dynamic name", "have dynamic names")
		evidence := dynamicReasons
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}

		log.Debug("PACKAGE_DYNAMIC_NAME check: violation",
			zap.Int("dynamic_count", len(dynamicPackages)))
		return checks.NewViolationOutput(n.Code, rationale, evidence, input), nil
	}

	log.Debug("PACKAGE_DYNAMIC_NAME check: compliant")
	return checks.NewCompliantOutput(
		n.Code,
		"All package names are simple string literals",
		input,
	), nil
}
