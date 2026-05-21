package dag

import (
	"context"
	"fmt"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/checks"
	"risk-guard/src/dag-impl/policy_loader"
	"risk-guard/src/lib/common/storage"
	"risk-guard/src/policy"
	"risk-guard/src/runpath"
	"time"

	"go.uber.org/zap"

	dag_builder "risk-guard/src/dag-builder"
	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"

	languageregistry "risk-guard/src/language/registry"
)

type DagResponse struct {
	Checks    []checks.Output
	Overrides map[string][]policy.PolicyOverride
}

func BuildAndRunDAG(ctx context.Context, input dag_impl.Input, build dag_builder.DagBuilder) (*DagResponse, error) {
	logger := ctxutil.GetLogger(ctx)
	totalStart := time.Now()
	defer func() {
		logger.Info("dag_total_complete", zap.Int64("duration_ms", time.Since(totalStart).Milliseconds()))
	}()

	dag := executiondag.NewDAG[dag_impl.Input]()

	logger.Debug("🔧 Building DAG...")

	langs := languageregistry.Languages()

	if err := build(dag, &input, langs, ctx); err != nil {
		return nil, fmt.Errorf("building dag: %w", err)
	}

	logger.Info("🚀 Executing DAG...")
	executeStart := time.Now()
	ctx, enrichedInput, err := dag.Execute(ctx, input)
	executeDurationMs := time.Since(executeStart).Milliseconds()
	logger.Info("dag_execute_complete", zap.Int64("duration_ms", executeDurationMs))
	if err != nil {
		return nil, fmt.Errorf("executing dag: %w", err)
	}

	logger.Debug("\n📝 Writing entries to storage...")
	entriesWriteStart := time.Now()
	entries := dag_builder.CollectEntries(ctx, dag, enrichedInput)
	backend := storage.MustGetBackend(ctx)
	outputDir := runpath.GetOutputDir(ctx)
	if err := backend.Metadata().WriteAll(ctx, outputDir, entries, enrichedInput); err != nil {
		return nil, fmt.Errorf("writing entries to storage: %w", err)
	}
	entriesWriteDurationMs := time.Since(entriesWriteStart).Milliseconds()
	logger.Info("dag_entries_write_complete",
		zap.Int("entry_count", len(entries)),
		zap.Int64("duration_ms", entriesWriteDurationMs),
	)
	logger.Info("   ✓ Wrote entries", zap.Int("count", len(entries)))

	if enrichedInput.WriteFetchOnly {
		return &DagResponse{}, nil
	}

	checkOutputs, err := dag_builder.AggregateChecks(ctx, dag)
	if err != nil {
		return nil, err
	}

	checksWriteStart := time.Now()
	err = checks.WriteCheckOutputs(ctx, enrichedInput, checkOutputs)
	checksWriteDurationMs := time.Since(checksWriteStart).Milliseconds()
	logger.Info("dag_checks_write_complete",
		zap.Int("check_count", len(checkOutputs)),
		zap.Int64("duration_ms", checksWriteDurationMs),
	)
	if err != nil {
		return nil, err
	}

	outputDir = runpath.GetOutputDir(ctx)
	summary := dag_builder.AggregateSummary(ctx, dag, checkOutputs, outputDir)
	summaryWriteStart := time.Now()
	err = dag_builder.WriteSummary(ctx, enrichedInput, summary)
	summaryWriteDurationMs := time.Since(summaryWriteStart).Milliseconds()
	logger.Info("dag_summary_write_complete", zap.Int64("duration_ms", summaryWriteDurationMs))
	if err != nil {
		return nil, err
	}

	response := &DagResponse{
		Checks: checkOutputs,
	}

	if enrichedInput.Trusted {
		policyOut, ok := executiondag.TryGetOutput[*policy_loader.Node](ctx)
		if ok {
			if output, ok := policyOut.(*policy_loader.Output); ok {
				response.Overrides = output.Overrides
			}
		}
	}

	return response, nil
}
