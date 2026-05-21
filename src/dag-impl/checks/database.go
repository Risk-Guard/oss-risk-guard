package checks

import (
	"context"
	"fmt"
	"risk-guard/src/ctxutil"
	"risk-guard/src/lib/common/depscache"
	"risk-guard/src/lib/common/storage"

	"go.uber.org/zap"

	dag_impl "risk-guard/src/dag-impl"
)

func WriteToStorage(ctx context.Context, checksDoc storage.ChecksResult, input dag_impl.Input) error {
	if input.AnalysisIdentifier == "" {
		panic("input.AnalysisIdentifier is required for Storage backend write but was empty")
	}

	log := ctxutil.GetLogger(ctx)
	backend := storage.MustGetBackend(ctx)
	dc := depscache.MustGet(ctx)

	freeDeps, lockfileEdges := extractDepsForStorage(ctx, input)

	policy, err := extractPolicyFromContext(ctx)
	if err != nil {
		return fmt.Errorf("extracting policy from context: %w", err)
	}

	err = backend.Checks().Insert(ctx, storage.ChecksInsertParams{
		Checks: checksDoc,
		Policy: policy,
	})
	if err != nil {
		return fmt.Errorf("inserting checks: %w", err)
	}

	log.Debug("wrote checks to storage",
		zap.String("analysis_id", input.AnalysisIdentifier),
		zap.Int("check_count", len(checksDoc.Checks)))

	if err := dc.SetTimestamp(ctx, input.AnalysisIdentifier, *checksDoc.AnalyzedAt); err != nil {
		return fmt.Errorf("setting timestamp in deps cache: %w", err)
	}

	if err := dc.StoreFreeDeps(ctx, input.AnalysisIdentifier, freeDeps); err != nil {
		return fmt.Errorf("storing free deps in deps cache: %w", err)
	}
	log.Debug("wrote deps to deps cache",
		zap.String("analysis_id", input.AnalysisIdentifier),
		zap.Int("deps_count", len(freeDeps)))

	if len(lockfileEdges) > 0 {
		if err := dc.StoreSourceLockfileV2(ctx, input.AnalysisIdentifier, lockfileEdges); err != nil {
			return fmt.Errorf("storing source lockfile in deps cache: %w", err)
		}
		log.Debug("wrote lockfile deps to deps cache",
			zap.String("analysis_id", input.AnalysisIdentifier),
			zap.Int("lockfile_edges_count", len(lockfileEdges)))
	}

	return nil
}
