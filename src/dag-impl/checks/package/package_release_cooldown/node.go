package package_release_cooldown

import (
	"context"
	"fmt"
	"risk-guard/src/category"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/language/dag/version_transformer"
	"time"

	"go.uber.org/zap"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
)

const defaultCooldownDays = 7

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "PACKAGE_RELEASE_COOLDOWN",
			Description: "Analyzed package version was published recently and has not had time for community vetting",
			Disclaimers: []string{
				fmt.Sprintf("Default cooldown threshold is %d days.", defaultCooldownDays),
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategorySecurityVulnerability: "Recently published versions have not been widely tested and may contain undiscovered vulnerabilities or supply chain compromise.",
				category.RiskCategoryContinuityAssurance:   "Very new releases carry higher risk of breaking changes or accidental publishes that may be yanked.",
			},
			Thresholds: map[string]any{
				"cooldown_days": defaultCooldownDays,
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*version_transformer.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	versionOut := executiondag.GetOutput[*version_transformer.Node](ctx).(*version_transformer.Output)

	cooldownDays := n.Thresholds["cooldown_days"].(int)

	var rationaleItems []string
	var evidence []string
	var compliantPackages []string

	for _, pkg := range input.Packages {
		versionMeta := versionOut.GetVersionMetadata(pkg.Ecosystem, pkg.Name)
		if versionMeta == nil {
			log.Warn("Version metadata not available",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name))
			continue
		}

		var releasedAt time.Time
		var resolvedVersion string

		if pkg.Version != "" {
			for i := range versionMeta.Versions {
				if versionMeta.Versions[i].Version == pkg.Version {
					releasedAt = versionMeta.Versions[i].ReleasedAt
					resolvedVersion = pkg.Version
					break
				}
			}
		} else if versionMeta.LatestVersion != nil {
			releasedAt = versionMeta.LatestVersion.ReleasedAt
			resolvedVersion = versionMeta.LatestVersion.Version
		}

		if resolvedVersion == "" {
			log.Warn("No version resolved for cooldown check",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.String("version", pkg.Version))
			continue
		}

		daysSinceRelease := int(time.Since(releasedAt).Hours() / 24)
		versionSuffix := "@" + resolvedVersion

		if daysSinceRelease < cooldownDays {
			item := fmt.Sprintf(
				"%s/%s%s: Released %d days ago (%s)",
				pkg.Ecosystem, pkg.Name, versionSuffix, daysSinceRelease, releasedAt.Format("2006-01-02"),
			)
			rationaleItems = append(rationaleItems, item)
			evidence = append(evidence, item)
		} else {
			compliant := fmt.Sprintf(
				"%s/%s%s: Released %d days ago",
				pkg.Ecosystem, pkg.Name, versionSuffix, daysSinceRelease,
			)
			compliantPackages = append(compliantPackages, compliant)
		}
	}

	if len(rationaleItems) > 0 {
		rationale := checks.BuildViolationRationale(rationaleItems, "", "")
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}
		return checks.NewViolationOutput(n.Code, rationale, evidence, input).
			WithThresholds(n.Thresholds), nil
	}

	return checks.NewCompliantOutput(n.Code, buildCompliantRationale(compliantPackages), input).WithThresholds(n.Thresholds), nil
}

func buildCompliantRationale(compliantPackages []string) string {
	if len(compliantPackages) == 0 {
		return "No packages checked"
	}
	if len(compliantPackages) == 1 {
		return compliantPackages[0]
	}
	return fmt.Sprintf("All %d packages passed the cooldown period", len(compliantPackages))
}
