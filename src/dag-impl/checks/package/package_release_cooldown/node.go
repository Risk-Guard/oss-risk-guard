package package_release_cooldown

import (
	"context"
	"fmt"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/version_transformer"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
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
	var unknownPackages []string

	for _, pkg := range input.Packages {
		versionMeta := versionOut.GetVersionMetadata(pkg.Ecosystem, pkg.Name)
		if versionMeta == nil {
			log.Info("Version metadata not available",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name))
			continue
		}

		var releasedAt *time.Time
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

		// Without a release date the cooldown cannot be evaluated. Reporting the
		// package as compliant would assert it cleared a period we never measured,
		// so it is listed as undetermined instead.
		if releasedAt == nil {
			log.Info("No release date available for cooldown check",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.String("version", resolvedVersion))
			unknownPackages = append(unknownPackages,
				fmt.Sprintf("%s/%s@%s: registry publishes no release date", pkg.Ecosystem, pkg.Name, resolvedVersion))
			continue
		}

		daysSinceRelease := int(time.Since(*releasedAt).Hours() / 24)
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
		evidence = append(evidence, unknownPackages...)
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}
		return checks.NewViolationOutput(n.Code, rationale, evidence, input).
			WithThresholds(n.Thresholds), nil
	}

	// Nothing was measurable: say so rather than reporting a pass nobody verified.
	if len(compliantPackages) == 0 && len(unknownPackages) > 0 {
		return checks.NewSkippedOutput(n.Code,
			fmt.Sprintf("Release dates unavailable for %d package(s)%s",
				len(unknownPackages), checks.FormatScannedItems(unknownPackages)), input).
			WithThresholds(n.Thresholds), nil
	}

	return checks.NewCompliantOutput(n.Code, buildCompliantRationale(compliantPackages, unknownPackages), input).WithThresholds(n.Thresholds), nil
}

func buildCompliantRationale(compliantPackages, unknownPackages []string) string {
	suffix := ""
	if len(unknownPackages) > 0 {
		suffix = fmt.Sprintf("; %d package(s) had no release date and were not evaluated", len(unknownPackages))
	}

	if len(compliantPackages) == 0 {
		return "No packages checked" + suffix
	}
	if len(compliantPackages) == 1 {
		return compliantPackages[0] + suffix
	}
	return fmt.Sprintf("All %d packages passed the cooldown period%s", len(compliantPackages), suffix)
}
