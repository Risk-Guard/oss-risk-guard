package source_no_license

import (
	"context"
	"fmt"
	"risk-guard/src/category"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/dag-impl/license_files"

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
			Code:        "SOURCE_NO_LICENSE",
			Description: "No license file found in source repository",
			Categories: map[category.RiskCategory]string{
				category.RiskCategoryCritical: "Without a license, the code is under exclusive copyright by default, making any use potentially infringing",
			},
		},
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*license_files.Node](),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	scannerOut := executiondag.GetOutput[*license_files.Node](ctx).(*license_files.Output)

	if len(scannerOut.Files) == 0 {
		log.Debug("SOURCE_NO_LICENSE check: violation")
		return checks.NewViolationOutput(
			n.Code,
			"No license file found in source repository",
			nil,
			input,
		), nil
	}

	log.Debug("SOURCE_NO_LICENSE check: compliant",
		zap.Int("license_count", len(scannerOut.Files)))
	return checks.NewCompliantOutput(
		n.Code,
		fmt.Sprintf("Found %d license file(s)", len(scannerOut.Files)),
		input,
	), nil
}
