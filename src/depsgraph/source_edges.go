package depsgraph

import (
	"context"
	"strings"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/lockfile"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/depscache"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"go.uber.org/zap"
)

func CollectEdgesForSource(ctx context.Context, sourceKey string) ([]DepsTreeEdge, error) {
	log := ctxutil.GetLogger(ctx)
	start := time.Now()
	var edges []DepsTreeEdge

	dc := depscache.MustGet(ctx)

	lockfileEdges, err := dc.GetSourceLockfile(ctx, sourceKey)
	if err != nil {
		return nil, err
	}
	for _, e := range lockfileEdges {
		edges = append(edges, DepsTreeEdge{
			DepsTreeEdge: models.DepsTreeEdge{
				ParentKey: e.ParentKey,
				ChildKey:  e.ChildKey,
				Ecosystem: ecosystemFromKey(e.ChildKey),
				Dev:       e.Dev,
				Location:  e.Location,
			},
		})
	}

	log.Debug("CollectEdgesForSource: lockfile edges fetched",
		zap.Int("lockfileEdgeCount", len(lockfileEdges)),
		zap.Duration("elapsed", time.Since(start)))

	bfsStart := time.Now()
	freeDeps, err := dc.CollectFreeDepsWithBFSTraversal(ctx, []string{sourceKey})
	if err != nil {
		return nil, err
	}

	var freeDepsEdges []DepsTreeEdge
	for parentKey, deps := range freeDeps {
		for _, dep := range deps {
			freeDepsEdges = append(freeDepsEdges, DepsTreeEdge{
				DepsTreeEdge: models.DepsTreeEdge{
					ParentKey: parentKey,
					ChildKey:  dep.AnalysisIdentifier,
					Ecosystem: ecosystemFromKey(dep.AnalysisIdentifier),
					Dev:       dep.Dev,
					Location:  dep.Location,
				},
			})
		}
	}
	propagateDevFlagForEdges(freeDepsEdges, sourceKey)
	edges = append(edges, freeDepsEdges...)

	log.Debug("CollectEdgesForSource: BFS free deps collected",
		zap.Int("parentKeys", len(freeDeps)),
		zap.Int("freeDepsEdgeCount", len(freeDepsEdges)),
		zap.Duration("bfsElapsed", time.Since(bfsStart)),
		zap.Duration("totalElapsed", time.Since(start)))

	return edges, nil
}

func ExtractUniqueKeys(rootKey string, edges []DepsTreeEdge) []string {
	seen := make(map[string]struct{}, len(edges)+1)
	seen[rootKey] = struct{}{}
	for _, edge := range edges {
		seen[edge.ChildKey] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	return keys
}

func propagateDevFlagForEdges(edges []DepsTreeEdge, rootKey string) {
	modelEdges := make([]models.DepsTreeEdge, len(edges))
	for i := range edges {
		modelEdges[i] = edges[i].DepsTreeEdge
	}
	lockfile.PropagateDevFlag(modelEdges, rootKey)
	for i := range edges {
		edges[i].Dev = modelEdges[i].Dev
	}
}

func ecosystemFromKey(key string) string {
	parts := strings.Split(key, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}
