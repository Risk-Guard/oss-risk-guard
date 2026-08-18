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
				"For monorepo-hosted packages, skew is measured against the newest commit anywhere in the repository, not just the package's subdirectory, and may be overstated.",
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
		return checks.NewSkippedOutput(n.Code, "No human commit history available", input), nil
	}

	var violations []string
	var caveats []string
	var compliantPackages []string
	var unknownPackages []string
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

		// The latest version wins outright once it is known, date or no date: its
		// missing date makes this package unmeasurable, whereas pkgMeta.ReleaseDate
		// describes the version under analysis and would measure commit skew
		// against the wrong release. The fallback is for having no version index
		// at all.
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

		// Without a release date there is no point to measure the newest commit
		// against. Counting the package as compliant would assert the source is in
		// step with a release nobody dated, so it is recorded as undetermined.
		if releaseDate == nil {
			log.Info("No release date available for unreleased changes check",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.String("version", latestVersion))
			unknownPackages = append(unknownPackages,
				fmt.Sprintf("%s/%s%s: registry publishes no release date", pkg.Ecosystem, pkg.Name, versionSuffix))
			continue
		}

		// Whole-repo latest commit. The metadata clone is treeless, so a
		// path-scoped "latest commit in the package's subdirectory" cannot be
		// derived cheaply; for a monorepo-hosted package this comparison uses the
		// newest commit anywhere in the repo and the caveat is recorded separately.
		latestCommit := gitMeta.LatestHumanCommit

		isMonorepo := pkgMeta.SourceDirectory != nil && *pkgMeta.SourceDirectory != ""

		skew := latestCommit.Sub(*releaseDate)
		daysAhead := int(skew.Hours() / 24)

		if daysAhead > skewDays {
			hasViolation = true
			item := fmt.Sprintf(
				"%s/%s%s: Source is %d days ahead of last release (committed %s, released %s)",
				pkg.Ecosystem, pkg.Name, versionSuffix,
				daysAhead,
				latestCommit.Format("2006-01-02"),
				releaseDate.Format("2006-01-02"),
			)
			violations = append(violations, item)

			// A monorepo-hosted package is measured against the newest commit
			// anywhere in the repo, not its subdirectory, so the skew above may be
			// overstated. Record that caveat as its own package-tagged evidence
			// line, held apart from violations so it never inflates the count of
			// violating packages that drives the rationale.
			if isMonorepo {
				caveats = append(caveats, fmt.Sprintf(
					"%s/%s%s: monorepo package under %s; skew measured against whole repository and may be overstated",
					pkg.Ecosystem, pkg.Name, versionSuffix, *pkgMeta.SourceDirectory,
				))
			}

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
		rationale := checks.BuildViolationRationale(violations, "", "") +
			checks.UnknownReleaseDateSuffix(len(unknownPackages))
		evidence := append(checks.TruncateEvidence(violations), caveats...)
		evidence = append(evidence, unknownPackages...)
		return checks.NewViolationOutput(n.Code, rationale, evidence, input).WithThresholds(n.Thresholds), nil
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
	return fmt.Sprintf("All %d packages are up to date with source%s", len(compliantPackages), suffix)
}
