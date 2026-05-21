package package_malformed_dependencies

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
			Code:        "PACKAGE_MALFORMED_DEPENDENCIES",
			Description: "Package declares dependencies with invalid or unparseable version constraints in registry metadata",
			Categories: map[category.RiskCategory]string{
				category.RiskCategorySecurityVulnerability: "Invalid dependency declarations can produce an inaccurate SBOM, masking vulnerable transitive dependencies.",
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

		var malformedDeps []string
		for _, dep := range pkgMeta.Dependencies {
			if dep.ParseError != nil && *dep.ParseError != "" {
				malformedDeps = append(malformedDeps, fmt.Sprintf("%s: %s", dep.AnalysisIdentifier, *dep.ParseError))
			}
		}

		if len(malformedDeps) > 0 {
			hasViolation = true
			for _, malformed := range malformedDeps {
				rationale := fmt.Sprintf(
					"%s/%s: Malformed dependency specifier - %s",
					pkg.Ecosystem, pkg.Name, malformed,
				)
				violations = append(violations, rationale)
			}
		} else {
			compliant := fmt.Sprintf(
				"%s/%s: All %d dependencies have valid specifiers",
				pkg.Ecosystem, pkg.Name, len(pkgMeta.Dependencies),
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

	rationale := checks.BuildCompliantRationale(compliantPackages, "No packages checked", "dependencies have valid specifiers")
	return checks.NewCompliantOutput(n.Code, rationale, input), nil
}
