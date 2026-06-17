package package_registry_quarantined

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
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
			Code:        "PACKAGE_REGISTRY_QUARANTINED",
			Description: "Package has been quarantined by the registry pending administrator review and cannot be installed",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryCritical: "The registry has frozen this package over suspected malware or abuse — an active takedown, not a benign missing name.",
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
	hasViolation := false

	for _, pkg := range input.Packages {
		registryResp := fetcherOut.GetRegistryResponse(pkg.Ecosystem, pkg.Name)

		if registryResp == nil {
			log.Warn("Registry response not available",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name))
			continue
		}

		// A quarantined project 404s on the detail endpoint but is flagged on the simple index.
		// Private packages legitimately have no public presence, so they cannot be quarantined.
		if registryResp.StatusCode == 404 && registryResp.ProjectStatus == language.ProjectStatusQuarantined && !pkg.Private {
			hasViolation = true
			meta := registry.MustGet(pkg.Ecosystem)
			pageURL := meta.BuildPackagePageURL(pkg.Name)
			rationale := fmt.Sprintf(
				"%s/%s: Quarantined by the registry pending admin review (%s)",
				pkg.Ecosystem, pkg.Name, pageURL,
			)
			violations = append(violations, rationale)
		}
	}

	if hasViolation {
		evidence := violations
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}
		return checks.NewViolationOutput(n.Code, buildRationale(violations), evidence, input), nil
	}

	return checks.NewCompliantOutput(n.Code, "No quarantined packages", input), nil
}

func buildRationale(violations []string) string {
	if len(violations) == 0 {
		return ""
	}
	return fmt.Sprintf("%d package(s) quarantined by the registry", len(violations))
}
