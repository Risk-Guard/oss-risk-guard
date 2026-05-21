package dag_builder

import (
	"context"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"time"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// AnalysisSummary contains the complete summary of an analysis run
type AnalysisSummary struct {
	AnalyzedAt    time.Time                  `json:"analyzed_at"`
	CheckSummary  CheckSummary               `json:"check_summary"`
	NodeSummaries []executiondag.NodeSummary `json:"node_summaries"`
}

// CheckSummary summarizes check results
type CheckSummary struct {
	Total          int      `json:"total"`
	Compliant      int      `json:"compliant"`
	Violations     int      `json:"violations"`
	Skipped        int      `json:"skipped"`
	ViolationCodes []string `json:"violation_codes,omitempty"`
}

// AggregateSummary collects summaries from all nodes and checks
func AggregateSummary(ctx context.Context, dag *executiondag.DAG[dag_impl.Input], checkOutputs []checks.Output, outputDir string) AnalysisSummary {
	summary := AnalysisSummary{
		AnalyzedAt:    time.Now(),
		CheckSummary:  aggregateCheckSummary(checkOutputs),
		NodeSummaries: []executiondag.NodeSummary{},
	}

	// Collect summaries from nodes
	for _, node := range dag.GetNodes() {
		// Get the output for this node
		output := node.GetOutput(ctx)
		if output == nil {
			continue
		}

		// Check if output implements OutputSummary
		if summarizable, ok := output.(executiondag.OutputSummary); ok {
			nodeSummary := summarizable.Summary(outputDir)
			if nodeSummary.Status != "" {
				summary.NodeSummaries = append(summary.NodeSummaries, nodeSummary)
			}
		}
	}

	return summary
}

// aggregateCheckSummary counts check results
func aggregateCheckSummary(checkOutputs []checks.Output) CheckSummary {
	var violations, compliant, skipped int
	var violationCodes []string

	for _, check := range checkOutputs {
		switch check.Check.CheckStatus {
		case "violation":
			violations++
			violationCodes = append(violationCodes, check.Check.CheckCode)
		case "compliant":
			compliant++
		case "skipped":
			skipped++
		}
	}

	return CheckSummary{
		Total:          len(checkOutputs),
		Compliant:      compliant,
		Violations:     violations,
		Skipped:        skipped,
		ViolationCodes: violationCodes,
	}
}

// WriteSummary writes the analysis summary to a file
func WriteSummary(ctx context.Context, input dag_impl.Input, summary AnalysisSummary) error {
	return checks.WriteSummary(ctx, input, summary)
}
