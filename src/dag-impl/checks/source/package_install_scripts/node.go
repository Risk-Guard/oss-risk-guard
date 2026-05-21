package package_install_scripts

import (
	"context"
	"fmt"
	"risk-guard/src/category"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/artifact_fetch"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/dag-impl/package_detector"
	"risk-guard/src/registry"
	"strings"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type Node struct {
	checks.BaseCheckNode
	extractors map[string]registry.ArtifactInstallScriptExtractor
}

func NewNode(extractors map[string]registry.ArtifactInstallScriptExtractor) *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "PACKAGE_INSTALL_SCRIPTS",
			Description: "Package contains scripts that execute during installation",

			Disclaimers: []string{
				// TODO: get the list of supported ecosystems programmatically from the extractors map
				"Detection coverage depends on ecosystem support.",
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategorySecurityVulnerability: "Install scripts execute arbitrary code on the consumer's machine during package installation, before any application code runs.",
			},
		},
		extractors: extractors,
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*package_detector.Node](),
		executiondag.DependsOn[*artifact_fetch.Node](),
	}
}

func (n *Node) AllowAutoSkip() bool {
	return false
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	if input.HasSourceKey() {
		detectorOut, ok := executiondag.TryGetOutput[*package_detector.Node](ctx)
		if ok && detectorOut.(executiondag.StatusProvider).GetStatus() == executiondag.StatusSuccess {
			return n.checkFromSource(ctx, input)
		}
	}

	artifactOut, ok := executiondag.TryGetOutput[*artifact_fetch.Node](ctx)
	if ok {
		output := artifactOut.(*artifact_fetch.Output)
		if output.GetStatus() == executiondag.StatusSuccess {
			return n.checkFromArtifacts(ctx, output, input)
		}
	}

	return checks.NewSkippedOutput(
		n.Code,
		"No source or artifact data available",
		input,
	), nil
}

func (n *Node) checkFromArtifacts(ctx context.Context, artifactOut *artifact_fetch.Output, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	var evidence []string

	for _, pkg := range input.Packages {
		extraction := artifactOut.GetExtraction(pkg.Ecosystem, pkg.Name)
		if extraction == nil || extraction.SkipReason != nil || len(extraction.Files) == 0 {
			continue
		}

		extractor, ok := n.extractors[pkg.Ecosystem]
		if !ok {
			continue
		}

		scripts, err := extractor.ExtractInstallScriptsFromFiles(extraction.Files)
		if err != nil {
			log.Debug("failed to extract install scripts from artifact",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.Error(err))
			continue
		}

		if len(scripts) > 0 {
			evidence = append(evidence, fmt.Sprintf("artifact %s/%s: %s",
				pkg.Ecosystem, pkg.Name, strings.Join(scripts, ", ")))
		}
	}

	if len(evidence) > 0 {
		rationale := checks.BuildViolationRationale(evidence, "has install-time scripts", "have install-time scripts")
		log.Debug("PACKAGE_INSTALL_SCRIPTS check: violation",
			zap.Int("count", len(evidence)))

		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}

		return checks.NewViolationOutput(n.Code, rationale, evidence, input), nil
	}

	var scanned []string
	for _, pkg := range input.Packages {
		scanned = append(scanned, fmt.Sprintf("%s/%s", pkg.Ecosystem, pkg.Name))
	}

	log.Debug("PACKAGE_INSTALL_SCRIPTS check: compliant (artifact)")
	return checks.NewCompliantOutput(
		n.Code,
		"No install-time scripts found in distributed artifacts"+checks.FormatScannedItems(scanned),
		input,
	), nil
}

func (n *Node) checkFromSource(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	detectorOut := executiondag.GetOutput[*package_detector.Node](ctx).(*package_detector.Output)
	manifests := detectorOut.DetectedManifests

	if len(manifests) == 0 {
		log.Debug("PACKAGE_INSTALL_SCRIPTS check: skipped - no package definitions found")
		return checks.NewSkippedOutput(
			n.Code,
			"No package definitions found in source code",
			input,
		), nil
	}

	var evidence []string
	for _, manifest := range manifests {
		if len(manifest.InstallScripts) > 0 {
			evidence = append(evidence, fmt.Sprintf("%s (%s): %s",
				manifest.Paths[0],
				manifest.Ecosystem,
				strings.Join(manifest.InstallScripts, ", ")))
		}
	}

	if len(evidence) > 0 {
		rationale := checks.BuildViolationRationale(evidence, "has install-time scripts", "have install-time scripts")
		log.Debug("PACKAGE_INSTALL_SCRIPTS check: violation",
			zap.Int("count", len(evidence)))

		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}

		return checks.NewViolationOutput(n.Code, rationale, evidence, input), nil
	}

	var scannedManifests []string
	for _, m := range manifests {
		if len(m.Paths) > 0 {
			scannedManifests = append(scannedManifests, m.Paths[0])
		}
	}

	log.Debug("PACKAGE_INSTALL_SCRIPTS check: compliant")
	return checks.NewCompliantOutput(
		n.Code,
		"No install-time scripts found in package definitions"+checks.FormatScannedItems(scannedManifests),
		input,
	), nil
}
