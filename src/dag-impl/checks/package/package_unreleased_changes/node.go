package package_unreleased_changes

import (
	"context"
	"fmt"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/version_transformer"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

const oneYearInDays = 365

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "PACKAGE_UNRELEASED_CHANGES",
			Description: "Source code has new commits not released to package registry",
			Disclaimers: []string{
				"Bot commits are excluded.",
				fmt.Sprintf("Default threshold is %d days.", oneYearInDays),
				"Uses the release date of the registry-designated latest version.",
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategorySecurityVulnerability: "Source improvements including security fixes are not being published to the package registry.",
				category.RiskCategoryTitleAssurance:        "The published artifact lags significantly behind the source, weakening provenance assurance.",
			},
			Thresholds: map[string]any{
				"skew_days": oneYearInDays,
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*transformer.Node](),
		executiondag.DependsOn[*git_clone_metadata.Node](),
		executiondag.DependsOn[*version_transformer.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)
	versionOut := executiondag.GetOutput[*version_transformer.Node](ctx).(*version_transformer.Output)

	metaOut := executiondag.GetOutput[*git_clone_metadata.Node](ctx).(*git_clone_metadata.Output)
	gitMeta := metaOut.GitMetadata()

	if gitMeta == nil {
		return nil, fmt.Errorf("git metadata is nil despite git_clone_metadata success")
	}

	if gitMeta.LatestHumanCommit == nil {
		return nil, fmt.Errorf("latest human commit is nil despite git_clone_metadata success")
	}

	var violations []string
	var compliantPackages []string
	hasViolation := false

	skewDays := n.Thresholds["skew_days"].(int)

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

		skew := gitMeta.LatestHumanCommit.Sub(*releaseDate)
		daysAhead := int(skew.Hours() / 24)

		if daysAhead > skewDays {
			hasViolation = true
			item := fmt.Sprintf(
				"%s/%s%s: Source is %d days ahead of last release (committed %s, released %s)",
				pkg.Ecosystem, pkg.Name, versionSuffix,
				daysAhead,
				gitMeta.LatestHumanCommit.Format("2006-01-02"),
				releaseDate.Format("2006-01-02"),
			)
			violations = append(violations, item)

			log.Debug("PACKAGE_UNRELEASED_CHANGES check: violation",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.Int("days_ahead", daysAhead))
		} else {
			compliant := fmt.Sprintf(
				"%s/%s%s: Source is %d days ahead of last release",
				pkg.Ecosystem, pkg.Name, versionSuffix, daysAhead,
			)
			compliantPackages = append(compliantPackages, compliant)

			log.Debug("PACKAGE_UNRELEASED_CHANGES check: compliant",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.Int("days_ahead", daysAhead))
		}
	}

	if hasViolation {
		rationale := checks.BuildViolationRationale(violations, "", "")
		evidence := checks.TruncateEvidence(violations)
		return checks.NewViolationOutput(n.Code, rationale, evidence, input).WithThresholds(n.Thresholds), nil
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
	return fmt.Sprintf("All %d packages are up to date with source", len(compliantPackages))
}
