package package_stale_release

import (
	"context"
	"fmt"
	"risk-guard/src/category"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/language/dag/transformer"
	"risk-guard/src/language/dag/version_transformer"
	"time"

	"go.uber.org/zap"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
)

const violationYears = 3

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "PACKAGE_STALE_RELEASE",
			Description: "Package has not been released or updated in a long time",
			Disclaimers: []string{
				fmt.Sprintf("Default threshold is %d years.", violationYears),
				"Uses the release date of the registry-designated latest version.",
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryContinuityAssurance:   "A package with no recent releases is harder to get bug fixes and compatibility updates for.",
				category.RiskCategorySecurityVulnerability: "The package is not being maintained with security patches or dependency updates.",
			},
			Thresholds: map[string]any{
				"violation_years": violationYears,
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*transformer.Node](),
		executiondag.DependsOn[*version_transformer.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)
	versionOut := executiondag.GetOutput[*version_transformer.Node](ctx).(*version_transformer.Output)

	violationYearsThreshold := n.Thresholds["violation_years"].(int)

	var rationaleItems []string
	var evidence []string
	var compliantPackages []string

	for _, pkg := range input.Packages {
		pkgMeta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name)

		if pkgMeta == nil {
			log.Warn("Package metadata not available",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name))
			continue
		}

		var releaseDate *time.Time
		var latestVersion string

		versionMeta := versionOut.GetVersionMetadata(pkg.Ecosystem, pkg.Name)
		if versionMeta != nil && versionMeta.LatestVersion != nil {
			releaseDate = &versionMeta.LatestVersion.ReleasedAt
			latestVersion = versionMeta.LatestVersion.Version
		} else if pkgMeta.ReleaseDate != nil {
			releaseDate = pkgMeta.ReleaseDate
			if pkgMeta.Version != nil {
				latestVersion = *pkgMeta.Version
			}
		}

		if releaseDate == nil {
			log.Warn("Package release date not available",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name))
			continue
		}

		versionSuffix := ""
		if latestVersion != "" {
			versionSuffix = "@" + latestVersion
		}

		daysSinceRelease := int(time.Since(*releaseDate).Hours() / 24)
		yearsSinceRelease := float64(daysSinceRelease) / 365.0

		if yearsSinceRelease >= float64(violationYearsThreshold) {
			item := fmt.Sprintf(
				"%s/%s%s: Package last released %d days ago (%.1f years)",
				pkg.Ecosystem, pkg.Name, versionSuffix, daysSinceRelease, yearsSinceRelease,
			)
			rationaleItems = append(rationaleItems, item)
			evidence = append(evidence, item)
		} else {
			compliant := fmt.Sprintf(
				"%s/%s%s: Package was released %d days ago (%.1f years)",
				pkg.Ecosystem, pkg.Name, versionSuffix, daysSinceRelease, yearsSinceRelease,
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
	return fmt.Sprintf("All %d packages have recent releases", len(compliantPackages))
}
