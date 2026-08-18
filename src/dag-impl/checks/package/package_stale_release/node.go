package package_stale_release

import (
	"context"
	"fmt"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/version_transformer"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
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
	var unknownPackages []string

	for _, pkg := range input.Packages {
		pkgMeta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name)

		if pkgMeta == nil {
			log.Info("Package metadata not available",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name))
			continue
		}

		var releaseDate *time.Time
		var latestVersion string

		// The latest version wins outright once it is known, date or no date: its
		// missing date makes this package unmeasurable, whereas pkgMeta.ReleaseDate
		// describes the version under analysis and would time staleness from the
		// wrong release. The fallback is for having no version index at all.
		versionMeta := versionOut.GetVersionMetadata(pkg.Ecosystem, pkg.Name)
		if versionMeta != nil && versionMeta.LatestVersion != nil {
			releaseDate = versionMeta.LatestVersion.ReleasedAt
			latestVersion = versionMeta.LatestVersion.Version
		} else if pkgMeta.ReleaseDate != nil {
			releaseDate = pkgMeta.ReleaseDate
			if pkgMeta.Version != nil {
				latestVersion = *pkgMeta.Version
			}
		}

		versionSuffix := ""
		if latestVersion != "" {
			versionSuffix = "@" + latestVersion
		}

		// Without a release date there is nothing to measure staleness from.
		// Counting the package as compliant would assert a recent release nobody
		// saw, so it is recorded as undetermined instead.
		if releaseDate == nil {
			log.Info("No release date available for stale release check",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.String("version", latestVersion))
			unknownPackages = append(unknownPackages,
				fmt.Sprintf("%s/%s%s: registry publishes no release date", pkg.Ecosystem, pkg.Name, versionSuffix))
			continue
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
		rationale := checks.BuildViolationRationale(rationaleItems, "", "") +
			checks.UnknownReleaseDateSuffix(len(unknownPackages))
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
	suffix := checks.UnknownReleaseDateSuffix(len(unknownPackages))

	if len(compliantPackages) == 0 {
		return "No packages checked" + suffix
	}
	if len(compliantPackages) == 1 {
		return compliantPackages[0] + suffix
	}
	return fmt.Sprintf("All %d packages have recent releases%s", len(compliantPackages), suffix)
}
