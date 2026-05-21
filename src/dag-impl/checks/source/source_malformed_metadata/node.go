package source_malformed_metadata

import (
	"context"
	"fmt"
	"risk-guard/src/category"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/dag-impl/package_detector"

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
			Code:        "SOURCE_MALFORMED_METADATA",
			Description: "Dependency files contain syntax errors or are malformed",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryCritical: "Source-to-package provenance cannot be determined when dependency files are unparseable.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{executiondag.DependsOn[*package_detector.Node]()}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	pkgDetectorOut := executiondag.GetOutput[*package_detector.Node](ctx).(*package_detector.Output)
	parseErrors := pkgDetectorOut.GetParseErrors()

	var allErrors []string
	for _, parseErr := range parseErrors {
		errMsg := fmt.Sprintf("%s: %s", parseErr.FilePath, parseErr.Error)
		allErrors = append(allErrors, errMsg)
	}

	if len(allErrors) > 0 {
		rationale := checks.BuildViolationRationale(allErrors, "has parse errors", "have parse errors")

		evidence := allErrors
		if len(evidence) > checks.MaxEvidenceItems {
			evidence = evidence[:checks.MaxEvidenceItems]
		}

		log.Debug("SOURCE_MALFORMED_METADATA check: violation",
			zap.String("rationale", rationale),
			zap.Int("error_count", len(allErrors)))
		return checks.NewViolationOutput(n.Code, rationale, evidence, input), nil
	}

	var scannedFiles []string
	for _, m := range pkgDetectorOut.DetectedManifests {
		if len(m.Paths) > 0 {
			scannedFiles = append(scannedFiles, m.Paths[0])
		}
	}

	log.Debug("SOURCE_MALFORMED_METADATA check: compliant")
	return checks.NewCompliantOutput(n.Code, "All dependency files parsed successfully"+checks.FormatScannedItems(scannedFiles), input), nil
}
