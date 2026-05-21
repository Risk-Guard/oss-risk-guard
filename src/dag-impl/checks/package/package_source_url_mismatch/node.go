package package_source_url_mismatch

import (
	"context"
	"fmt"
	"risk-guard/src/category"
	"risk-guard/src/common"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/language/dag/transformer"
	"strings"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "PACKAGE_SOURCE_URL_MISMATCH",
			Description: "Package registry reports different source repository than analyzed repository",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryTitleAssurance: "A mismatched source URL raises doubt about whether the package and source repository share the same author.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*transformer.Node](),
	}
}

// normalizeAndCompareURLs compares two URLs after normalization.
// Returns true if URLs are considered equal, false otherwise.
func normalizeAndCompareURLs(url1, url2 string) bool {
	normalized1 := common.NormalizeSourceURL(url1)
	normalized2 := common.NormalizeSourceURL(url2)

	// Also normalize http/https
	normalized1 = strings.ReplaceAll(normalized1, "http://", "https://")
	normalized2 = strings.ReplaceAll(normalized2, "http://", "https://")

	return normalized1 == normalized2
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	// If no source URL in input, skip this check (can't compare)
	if !input.HasSourceURL() {
		log.Debug("PACKAGE_SOURCE_URL_MISMATCH check: skipped - no source URL in input")
		return checks.NewSkippedOutput(
			n.Code,
			"No source URL provided for comparison",
			input,
		), nil
	}

	inputSourceURL := *input.SourceURL

	// Get transformer output - DAG guarantees it succeeded
	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)

	var violations []string
	var compliantPackages []string
	hasViolation := false

	for _, pkg := range input.Packages {
		pkgMeta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name)

		// If no metadata or no sourceURL in metadata, skip this package
		if pkgMeta == nil || pkgMeta.SourceURL == nil || *pkgMeta.SourceURL == "" {
			log.Debug("Skipping package - no registry sourceURL",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name))
			continue
		}

		registrySourceURL := *pkgMeta.SourceURL

		// Compare normalized URLs
		if !normalizeAndCompareURLs(inputSourceURL, registrySourceURL) {
			hasViolation = true
			rationale := fmt.Sprintf(
				"%s/%s: Registry reports source URL %q but analyzing repository %q",
				pkg.Ecosystem, pkg.Name, registrySourceURL, inputSourceURL,
			)
			violations = append(violations, rationale)

			log.Debug("PACKAGE_SOURCE_URL_MISMATCH check: violation detected",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.String("input_url", inputSourceURL),
				zap.String("registry_url", registrySourceURL))
		} else {
			compliant := fmt.Sprintf(
				"%s/%s: Source URL matches registry",
				pkg.Ecosystem, pkg.Name,
			)
			compliantPackages = append(compliantPackages, compliant)
		}
	}

	if hasViolation {
		rationale := fmt.Sprintf("%d package(s) with source URL mismatch", len(violations))
		evidence := violations
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}
		return checks.NewViolationOutput(n.Code, rationale, evidence, input), nil
	}

	if len(compliantPackages) > 0 {
		rationale := buildCompliantRationale(compliantPackages)
		return checks.NewCompliantOutput(n.Code, rationale, input), nil
	}

	// No packages had registry sourceURL to compare
	log.Debug("PACKAGE_SOURCE_URL_MISMATCH check: skipped - no registry sourceURL for any package")
	return checks.NewSkippedOutput(
		n.Code,
		"No registry source URL available for comparison",
		input,
	), nil
}

func buildCompliantRationale(compliantPackages []string) string {
	if len(compliantPackages) == 0 {
		return "No packages checked"
	}
	if len(compliantPackages) == 1 {
		return compliantPackages[0]
	}
	return fmt.Sprintf("All %d packages have matching source URLs", len(compliantPackages))
}
