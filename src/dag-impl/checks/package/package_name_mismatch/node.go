package package_name_mismatch

import (
	"context"
	"fmt"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector_published"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

// Use storage.CheckStatus type aliases for cleaner code
type checkStatus = storage.CheckStatus

const (
	statusCompliant = storage.StatusCompliant
	statusViolation = storage.StatusViolation
	statusSkipped   = storage.StatusSkipped
)

type Node struct {
	checks.BaseCheckNode
	ecosystemUtils map[string]language.EcosystemUtils
}

func NewNode(languages map[string]language.Language) *Node {
	ecosystemUtils := make(map[string]language.EcosystemUtils, len(languages))
	for ecosystem, lang := range languages {
		ecosystemUtils[ecosystem] = lang
	}
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "PACKAGE_NAME_MISMATCH",
			Description: "Published package has different name than source repository",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryCritical: "A name mismatch between published package and source repository enables package impersonation or substitution attacks.",
			},
		},
		ecosystemUtils: ecosystemUtils,
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*git_clone_metadata.Node](),
		executiondag.DependsOn[*package_detector_published.Node](),
		executiondag.DependsOn[*transformer.Node](),
	}
}

func filterNonDynamicManifests(manifests []models.ManifestResult) ([]models.ManifestResult, bool) {
	var nonDynamicManifests []models.ManifestResult
	var hasDynamicNames bool

	for _, m := range manifests {
		if m.IsDynamic {
			hasDynamicNames = true
		} else if m.Name != nil {
			nonDynamicManifests = append(nonDynamicManifests, m)
		}
	}

	return nonDynamicManifests, hasDynamicNames
}

// formatPkgRef renders "ecosystem/name@version" (version omitted when unknown).
func formatPkgRef(pkgInfo models.PackageInfo) string {
	ref := fmt.Sprintf("%s/%s", pkgInfo.Ecosystem, pkgInfo.Name)
	if pkgInfo.Version != "" {
		ref += "@" + pkgInfo.Version
	}
	return ref
}

func buildEvidenceForMismatch(pkgInfo models.PackageInfo, matchingManifests []models.ManifestResult, gitMeta *models.GitMetadata, gitHeadUsed bool, sourceCommit string) []string {
	var evidence []string

	evidence = append(evidence,
		fmt.Sprintf("Package name: %s/%s", pkgInfo.Ecosystem, pkgInfo.Name),
		fmt.Sprintf("Source Code: %s", gitMeta.SourceURL),
	)

	if len(matchingManifests) > 0 {
		var allPkgs []string
		displayManifests := matchingManifests
		if len(displayManifests) > checks.MaxEvidenceItems {
			displayManifests = displayManifests[:checks.MaxEvidenceItems]
		}
		for _, m := range displayManifests {
			allPkgs = append(allPkgs, fmt.Sprintf("%s (%s)", *m.Name, m.Paths[0]))
		}
		suffix := ""
		if len(matchingManifests) > checks.MaxEvidenceItems {
			suffix = fmt.Sprintf(", ... and %d more", len(matchingManifests)-checks.MaxEvidenceItems)
		}
		evidence = append(evidence,
			fmt.Sprintf("Packages found in source (%d total): %s%s", len(matchingManifests), strings.Join(allPkgs, ", "), suffix),
		)
	}

	// Disclose which source ref this comparison was made against, so a mismatch
	// against a diverged HEAD isn't mistaken for a scan of the as-published source.
	provenance := checks.ScannedProvenance(gitHeadUsed, sourceCommit, formatPkgRef(pkgInfo))
	if gitHeadUsed {
		provenance += " — name is absent from the exact published commit"
	}
	evidence = append(evidence, provenance)

	return evidence
}

func buildFinalRationale(rationales []string) string {
	if len(rationales) == 0 {
		return "No package metadata available for any package"
	}
	if len(rationales) == 1 {
		return rationales[0]
	}
	display := rationales
	suffix := ""
	if len(display) > checks.MaxEvidenceItems {
		display = display[:checks.MaxEvidenceItems]
		suffix = fmt.Sprintf("; ... and %d more", len(rationales)-checks.MaxEvidenceItems)
	}
	return fmt.Sprintf("%d packages checked: %s%s", len(rationales), strings.Join(display, "; "), suffix)
}

func (n *Node) checkPackageNameMatch(
	pkgInfo models.PackageInfo,
	nonDynamicManifests []models.ManifestResult,
	gitMeta *models.GitMetadata,
	transformerOut *transformer.Output,
	allPackages []models.PackageInfo,
	gitHeadUsed bool,
	sourceCommit string,
	log *zap.Logger,
) (checkStatus, string, []string, error) {
	utils := language.MustGetEcosystemUtils(n.ecosystemUtils, pkgInfo.Ecosystem)
	publishedName := utils.NormalizeName(pkgInfo.Name)

	var sourceNames []string
	var matchingManifests []models.ManifestResult
	matchFound := false

	for _, m := range nonDynamicManifests {
		if m.Ecosystem == pkgInfo.Ecosystem {
			manifestUtils := language.MustGetEcosystemUtils(n.ecosystemUtils, m.Ecosystem)
			sourceName := manifestUtils.NormalizeName(*m.Name)
			sourceNames = append(sourceNames, *m.Name)
			matchingManifests = append(matchingManifests, m)

			if sourceName == publishedName {
				matchFound = true
				break
			}
		}
	}

	if !matchFound {
		var rationale string
		var evidence []string

		if len(sourceNames) == 0 {
			rationale = fmt.Sprintf("%s/%s: No %s package definitions found in source code (see SOURCE_PACKAGE_NAME_UNEXPORTED)",
				pkgInfo.Ecosystem, pkgInfo.Name, pkgInfo.Ecosystem)
			return statusSkipped, rationale, nil, nil
		} else {
			rationale = fmt.Sprintf("%s/%s: Package not found among %d packages in source code %s",
				pkgInfo.Ecosystem, pkgInfo.Name, len(sourceNames), gitMeta.SourceURL)
			evidence = buildEvidenceForMismatch(pkgInfo, matchingManifests, gitMeta, gitHeadUsed, sourceCommit)
		}

		if transformerOut != nil {
			overlapEvidence := n.computeMaintainerOverlapEvidence(pkgInfo, transformerOut, allPackages, matchingManifests, log)
			if overlapEvidence != "" {
				evidence = append(evidence, overlapEvidence)
			}
		}

		log.Debug("PACKAGE_NAME_MISMATCH check: violation detected",
			zap.String("ecosystem", pkgInfo.Ecosystem),
			zap.String("package", pkgInfo.Name),
			zap.Strings("source_names", sourceNames))

		return statusViolation, rationale, evidence, nil
	}

	rationale := fmt.Sprintf("%s/%s: Package name matches source code", pkgInfo.Ecosystem, pkgInfo.Name)
	return statusCompliant, rationale, nil, nil
}

func (n *Node) computeMaintainerOverlapEvidence(
	mismatchedPkg models.PackageInfo,
	transformerOut *transformer.Output,
	allPackages []models.PackageInfo,
	sourceManifests []models.ManifestResult,
	log *zap.Logger,
) string {
	mismatchedMeta := transformerOut.GetPackageMetadata(mismatchedPkg.Ecosystem, mismatchedPkg.Name)
	if mismatchedMeta == nil || len(mismatchedMeta.Maintainers) == 0 {
		return ""
	}

	for _, m := range sourceManifests {
		if m.IsDynamic {
			continue
		}

		for _, pkg := range allPackages {
			if pkg.Ecosystem != m.Ecosystem {
				continue
			}

			manifestUtils := language.MustGetEcosystemUtils(n.ecosystemUtils, m.Ecosystem)
			pkgUtils := language.MustGetEcosystemUtils(n.ecosystemUtils, pkg.Ecosystem)
			if m.Name == nil || manifestUtils.NormalizeName(*m.Name) != pkgUtils.NormalizeName(pkg.Name) {
				continue
			}

			comparisonMeta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name)
			if comparisonMeta == nil || len(comparisonMeta.Maintainers) == 0 {
				continue
			}

			overlap := ComputeMaintainerOverlap(mismatchedMeta.Maintainers, comparisonMeta.Maintainers)
			overlap.ComparedTo = fmt.Sprintf("%s/%s", pkg.Ecosystem, pkg.Name)

			return FormatMaintainerOverlapEvidence(overlap)
		}
	}

	return ""
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	metaOut := executiondag.GetOutput[*git_clone_metadata.Node](ctx).(*git_clone_metadata.Output)
	gitMeta := metaOut.GitMetadata()

	detectorOut := executiondag.GetOutput[*package_detector_published.Node](ctx).(*package_detector_published.Output)
	manifests := detectorOut.DetectedManifests
	gitHeadUsed := detectorOut.GitHeadUsed()
	sourceCommit := detectorOut.SourceCommit

	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)

	if gitMeta == nil {
		return nil, fmt.Errorf("git metadata is nil despite git_clone_metadata success")
	}

	if len(manifests) == 0 {
		log.Debug("PACKAGE_NAME_MISMATCH check: skipped - no package definitions found")
		return checks.NewSkippedOutput(
			n.Code,
			"Could not find any package definitions in source code",
			input,
		), nil
	}

	nonDynamicManifests, hasDynamicNames := filterNonDynamicManifests(manifests)

	if len(nonDynamicManifests) == 0 && hasDynamicNames {
		log.Debug("PACKAGE_NAME_MISMATCH check: skipped - only dynamic package names")
		return checks.NewSkippedOutput(
			n.Code,
			"Package name is dynamically determined (see DYNAMIC_PACKAGE_NAME check)",
			input,
		), nil
	}

	worstStatus := statusSkipped
	var violationRationales []string
	var otherRationales []string
	var allEvidence []string

	for _, pkgInfo := range input.Packages {
		status, rationale, evidence, err := n.checkPackageNameMatch(pkgInfo, nonDynamicManifests, gitMeta, transformerOut, input.Packages, gitHeadUsed, sourceCommit, log)
		if err != nil {
			return nil, fmt.Errorf("checking package name match for %s/%s: %w", pkgInfo.Ecosystem, pkgInfo.Name, err)
		}

		if status == statusViolation {
			violationRationales = append(violationRationales, rationale)
			worstStatus = statusViolation
			allEvidence = append(allEvidence, evidence...)
		} else {
			otherRationales = append(otherRationales, rationale)
			if status == statusCompliant && worstStatus != statusViolation {
				worstStatus = statusCompliant
			}
		}
	}

	finalRationale := buildFinalRationale(append(violationRationales, otherRationales...))

	switch worstStatus {
	case statusViolation:
		log.Debug("PACKAGE_NAME_MISMATCH check: violation", zap.String("rationale", finalRationale))
		evidence := allEvidence
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}
		return checks.NewViolationOutput(n.Code, finalRationale, evidence, input), nil
	case statusCompliant:
		log.Debug("PACKAGE_NAME_MISMATCH check: compliant", zap.String("rationale", finalRationale))
		// Disclose the assurance level: a match at the exact published gitHead is
		// stronger than one merely against current HEAD.
		var matchEvidence string
		if gitHeadUsed {
			matchEvidence = "Matched at " + checks.SourceProvenance(true, sourceCommit, "")
		} else {
			matchEvidence = "Matched against repository HEAD — no gitHead recorded; not verified against the exact published commit"
		}
		return checks.NewCompliantOutput(n.Code, finalRationale, input).WithEvidence(matchEvidence), nil
	default:
		log.Debug("PACKAGE_NAME_MISMATCH check: skipped", zap.String("rationale", finalRationale))
		return checks.NewSkippedOutput(n.Code, finalRationale, input), nil
	}
}
