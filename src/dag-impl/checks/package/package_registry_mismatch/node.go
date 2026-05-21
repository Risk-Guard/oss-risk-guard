package package_registry_mismatch

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/fetcher"
	"github.com/Risk-Guard/oss-risk-guard/src/language/registry"

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
			Code:        "PACKAGE_REGISTRY_MISMATCH",
			Description: "Package does not exist in the package registry, or claims to be private but is published",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryCritical: "Package-to-source metadata round-trip cannot be verified, preventing provenance confirmation.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*fetcher.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	fetcherOut := executiondag.GetOutput[*fetcher.Node](ctx).(*fetcher.Output)

	var violations []string
	var compliantPackages []string
	hasViolation := false

	for _, pkg := range input.Packages {
		registryResp := fetcherOut.GetRegistryResponse(pkg.Ecosystem, pkg.Name)

		if registryResp == nil {
			log.Warn("Registry response not available",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name))
			continue
		}

		switch registryResp.StatusCode {
		case 404:
			if pkg.Private {
				compliant := fmt.Sprintf(
					"%s/%s: Private package correctly not in public registry",
					pkg.Ecosystem, pkg.Name,
				)
				compliantPackages = append(compliantPackages, compliant)
			} else {
				hasViolation = true
				meta := registry.MustGet(pkg.Ecosystem)
				pageURL := meta.BuildPackagePageURL(pkg.Name)
				rationale := fmt.Sprintf(
					"%s/%s: Package not found in public registry (%s)",
					pkg.Ecosystem, pkg.Name, pageURL,
				)
				violations = append(violations, rationale)
			}
		case 200:
			if pkg.Private {
				hasViolation = true
				meta := registry.MustGet(pkg.Ecosystem)
				pageURL := meta.BuildPackagePageURL(pkg.Name)
				rationale := fmt.Sprintf(
					"%s/%s: Package claims private but exists in public registry (%s)",
					pkg.Ecosystem, pkg.Name, pageURL,
				)
				violations = append(violations, rationale)
			} else {
				compliant := fmt.Sprintf(
					"%s/%s: Package found in registry",
					pkg.Ecosystem, pkg.Name,
				)
				compliantPackages = append(compliantPackages, compliant)
			}
		default:
			log.Warn("Registry returned non-200 status",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.Int("status_code", registryResp.StatusCode))
		}
	}

	if hasViolation {
		evidence := violations
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}
		return checks.NewViolationOutput(n.Code, buildRationale(violations), evidence, input), nil
	}

	return checks.NewCompliantOutput(n.Code, buildCompliantRationale(compliantPackages), input), nil
}

func buildRationale(violations []string) string {
	if len(violations) == 0 {
		return ""
	}
	return fmt.Sprintf("%d package(s) with registry mismatch", len(violations))
}

func buildCompliantRationale(compliantPackages []string) string {
	if len(compliantPackages) == 0 {
		return "No packages checked"
	}
	if len(compliantPackages) == 1 {
		return compliantPackages[0]
	}
	return fmt.Sprintf("All %d packages found in registry", len(compliantPackages))
}
