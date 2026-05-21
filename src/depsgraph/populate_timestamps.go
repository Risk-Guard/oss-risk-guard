package depsgraph

import (
	"context"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/depscache"
)

func PopulateTimestamps(ctx context.Context, edges []DepsTreeEdge) error {
	if len(edges) == 0 {
		return nil
	}

	keys := make([]string, 0, len(edges))
	seen := make(map[string]struct{})
	for _, e := range edges {
		if _, ok := seen[e.ChildKey]; !ok {
			seen[e.ChildKey] = struct{}{}
			keys = append(keys, e.ChildKey)
		}
	}

	timestamps, err := depscache.MustGet(ctx).GetTimestampBatch(ctx, keys)
	if err != nil {
		return err
	}

	for i := range edges {
		edges[i].ChildAnalyzedAt = timestamps[edges[i].ChildKey]
	}

	return nil
}
