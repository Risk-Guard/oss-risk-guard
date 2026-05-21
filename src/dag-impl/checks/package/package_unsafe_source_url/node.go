package package_unsafe_source_url

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

const CheckCode = "PACKAGE_UNSAFE_SOURCE_URL"

type Node struct {
	checks.BaseCheckNode
}

func NewNode() *Node {
	return &Node{
		BaseCheckNode: checks.BaseCheckNode{
			Code:        CheckCode,
			Description: "Package metadata contains invalid or unsafe source URLs",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryCritical: "Source code cannot be independently verified when package metadata contains invalid or unsafe URLs.",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*transformer.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	// Get transformer output
	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)

	// Check if there are any rejected URLs
	if len(transformerOut.RejectedSourceURLs) == 0 {
		log.Debug("no invalid source URLs found")
		rationale := "All package source URLs are valid and use secure protocols"
		return checks.NewCompliantOutput(CheckCode, rationale, input), nil
	}

	// Build evidence list from rejections
	var evidence []string
	for _, rejection := range transformerOut.RejectedSourceURLs {
		evidenceItem := fmt.Sprintf("%s/%s: registry metadata contains %s (%s)",
			rejection.Ecosystem,
			rejection.PackageName,
			rejection.InvalidURL,
			rejection.RejectReason)
		evidence = append(evidence, evidenceItem)
	}

	log.Warn("detected invalid source URLs in package metadata",
		zap.Int("count", len(transformerOut.RejectedSourceURLs)))

	rationale := checks.BuildViolationRationale(evidence, "", "")

	if len(evidence) > checks.MaxEvidenceItems {
		evidence = evidence[:checks.MaxEvidenceItems]
	}

	return checks.NewViolationOutput(CheckCode, rationale, evidence, input), nil
}
