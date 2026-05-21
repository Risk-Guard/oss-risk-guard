package package_no_license

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"

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
			Code:        "PACKAGE_NO_LICENSE",
			Description: "Package does not declare a license in registry metadata",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryLicenseCompliance: "Without license metadata in the registry, consumers cannot determine usage rights.",
				category.RiskCategoryTitleAssurance:    "Absence of license documentation weakens confidence in package ownership and provenance.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*transformer.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)

	var violations []string
	var compliantPackages []string
	hasViolation := false

	for _, pkg := range input.Packages {
		pkgMeta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name)

		if pkgMeta == nil {
			log.Warn("Package metadata not available",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name))
			continue
		}

		if pkgMeta.Status == "version_not_found" {
			reason := "version not found in registry"
			if pkgMeta.StatusReason != nil {
				reason = *pkgMeta.StatusReason
			}
			rationale := fmt.Sprintf("%s/%s: %s", pkg.Ecosystem, pkg.Name, reason)
			return checks.NewSkippedOutput(n.Code, rationale, input), nil
		}

		if !pkgMeta.HasLicense() {
			hasViolation = true
			rationale := fmt.Sprintf(
				"%s/%s: Package does not declare a license",
				pkg.Ecosystem, pkg.Name,
			)
			violations = append(violations, rationale)
		} else {
			compliant := fmt.Sprintf(
				"%s/%s: Package declares a license",
				pkg.Ecosystem, pkg.Name,
			)
			compliantPackages = append(compliantPackages, compliant)
		}
	}

	if hasViolation {
		rationale := checks.BuildViolationRationale(violations, "", "")
		evidence := violations
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}
		return checks.NewViolationOutput(n.Code, rationale, evidence, input), nil
	}

	rationale := checks.BuildCompliantRationale(compliantPackages, "No packages checked", "packages declare licenses")
	return checks.NewCompliantOutput(n.Code, rationale, input), nil
}
