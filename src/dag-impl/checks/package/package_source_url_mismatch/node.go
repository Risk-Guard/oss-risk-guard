package package_source_url_mismatch

import (
	"context"
	"fmt"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/git"

	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_invalid_artifact"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/provenance_verify"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/provenance"

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
		executiondag.DependsOn[*provenance_verify.Node](),
		executiondag.DependsOn[*package_invalid_artifact.Node](),
	}
}

// AllowAutoSkip returns false so this check still runs when PACKAGE_INVALID_ARTIFACT
// or its dependencies skip — it must be able to observe that check's verdict to
// decide whether to defer, and to read provenance for a signed repo mismatch.
func (n *Node) AllowAutoSkip() bool { return false }

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

// resolveComparisonURL returns the canonical repository URL to compare against a
// package's registry-declared source URL. A remote scan already supplies a URL,
// returned unchanged. A local scan supplies an on-disk path whose canonical
// identity is its git "origin" remote; ok is false when no origin is configured
// (nothing meaningful to compare — the caller should skip the check).
func resolveComparisonURL(ctx context.Context, sourceURL string) (string, bool) {
	if isLocal, _ := common.IsLocalPath(sourceURL); !isLocal {
		return sourceURL, true
	}
	host, owner, repo, ok, err := git.GetOriginOwnerRepo(ctx, sourceURL)
	if err != nil || !ok {
		return "", false
	}
	return "https://" + host + "/" + owner + "/" + repo, true
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

	// A cryptographically invalid artifact (CRITICAL) dominates; a source-URL
	// mismatch is lower-signal context on top of it, so defer to that finding.
	invalidOut := executiondag.GetOutput[*package_invalid_artifact.Node](ctx).(*checks.Output)
	if invalidOut.Check.CheckStatus == storage.StatusViolation {
		log.Debug("PACKAGE_SOURCE_URL_MISMATCH check: deferred to PACKAGE_INVALID_ARTIFACT")
		return checks.NewSkippedOutput(n.Code, "Deferred to PACKAGE_INVALID_ARTIFACT", input), nil
	}

	provOut := executiondag.GetOutput[*provenance_verify.Node](ctx).(*provenance_verify.Output)

	// Get transformer output - DAG guarantees it succeeded
	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)

	// For a local scan, input.SourceURL is the on-disk path (e.g.
	// /Users/me/pytorch), not a repository URL. Resolve its canonical identity
	// from the git origin remote so the comparison below is URL-against-URL. A
	// local source with no resolvable origin has nothing canonical to compare,
	// so skip rather than diff a registry URL against a filesystem path (which
	// can never match, a guaranteed false positive).
	compareURL, ok := resolveComparisonURL(ctx, inputSourceURL)
	if !ok {
		log.Debug("PACKAGE_SOURCE_URL_MISMATCH check: skipped - local source has no resolvable git origin remote",
			zap.String("path", inputSourceURL))
		return checks.NewSkippedOutput(
			n.Code,
			"Local source has no git origin remote to compare against the registry",
			input,
		), nil
	}
	inputSourceURL = compareURL

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

	// A validly-signed build provenance that attests a different repo than the one
	// analyzed is a high-confidence source mismatch, independent of (and stronger
	// than) the registry's own self-reported repository field.
	if provOut.FailReason == string(provenance.FailRepoMismatch) && provOut.SourceRepo != "" {
		hasViolation = true
		violations = append(violations, fmt.Sprintf(
			"Build provenance (cryptographically signed) attests source repository %q, not the analyzed repository %q",
			provOut.SourceRepo, inputSourceURL))
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
