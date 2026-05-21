package source_manifest_without_lockfile

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        "SOURCE_MANIFEST_WITHOUT_LOCKFILE",
			Description: "Source repository contains manifest files without corresponding lockfiles",
			Outcomes: storage.Outcomes{
				storage.StatusSkipped: "Lockfile analysis not needed for package scans",
			},
			Disclaimers: []string{
				"Lockfile detection coverage depends on ecosystem support.",
			},
			Categories: map[category.RiskCategory]string{
				category.RiskCategorySecurityVulnerability: "Without lockfiles the SBOM may not accurately reflect resolved dependency versions.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{executiondag.DependsOn[*package_detector.Node]()}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	if !input.HasSourceKey() {
		var pkgs []string
		for _, pkg := range input.Packages {
			pkgs = append(pkgs, fmt.Sprintf("%s/%s", pkg.Ecosystem, pkg.Name))
		}
		return checks.NewSkippedOutput(n.Code, "Lockfile analysis not needed for package scans"+checks.FormatScannedItems(pkgs), input), nil
	}

	detectorOut := executiondag.GetOutput[*package_detector.Node](ctx).(*package_detector.Output)

	var missing []string
	for _, manifest := range detectorOut.DetectedManifests {
		if manifest.Lockfile == nil {
			path := manifest.Paths[0]
			missing = append(missing, fmt.Sprintf("[%s] %s", manifest.Ecosystem, path))
		}
	}

	totalManifests := len(detectorOut.DetectedManifests)

	if totalManifests == 0 {
		return checks.NewCompliantOutput(n.Code, "No manifest files found", input), nil
	}

	if len(missing) == 0 {
		var manifestPaths []string
		for _, m := range detectorOut.DetectedManifests {
			if len(m.Paths) > 0 {
				manifestPaths = append(manifestPaths, m.Paths[0])
			}
		}
		return checks.NewCompliantOutput(n.Code,
			fmt.Sprintf("All %d manifest(s) have lockfiles", totalManifests)+checks.FormatScannedItems(manifestPaths), input), nil
	}

	rationale := checks.BuildViolationRationale(missing, "has no lockfile", "have no lockfiles")

	return checks.NewViolationOutput(n.Code, rationale, checks.TruncateEvidence(missing), input), nil
}
