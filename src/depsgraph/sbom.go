package depsgraph

import (
	"context"
	"fmt"
	"risk-guard/src/lib/common/depscache"
	"risk-guard/src/lib/common/storage"
	"risk-guard/src/models"
	"strings"
)

// edgesToDepsMap converts lockfile/BFS edges into a parent→child-keys map for SBOM dep population.
func edgesToDepsMap(edges []DepsTreeEdge) map[string][]string {
	result := make(map[string][]string, len(edges))
	for _, e := range edges {
		result[e.ParentKey] = append(result[e.ParentKey], e.ChildKey)
	}
	return result
}

// bfsMapToDepsMap converts the BFS traversal output into a parent→child-keys map.
func bfsMapToDepsMap(bfsMap map[string][]models.Dependency) map[string][]string {
	result := make(map[string][]string, len(bfsMap))
	for parentKey, deps := range bfsMap {
		for _, dep := range deps {
			if dep.AnalysisIdentifier != "" {
				result[parentKey] = append(result[parentKey], dep.AnalysisIdentifier)
			}
		}
	}
	return result
}

const sbomBatchSize = 1000

// CollectSBOMNodes fetches SBOM metadata for a source and all its dependencies.
// Gets dependency graph from Valkey, then fetches rich metadata from GCS.
func CollectSBOMNodes(ctx context.Context, backend storage.ChecksBackend, rootKey string) ([]SBOMNode, error) {
	edges, err := CollectEdgesForSource(ctx, rootKey)
	if err != nil {
		return nil, fmt.Errorf("collecting edges: %w", err)
	}

	keys := ExtractUniqueKeys(rootKey, edges)
	depsMap := edgesToDepsMap(edges)

	return batchFetchSBOMNodes(ctx, backend, keys, depsMap)
}

// CollectSBOMNodesForPackage fetches SBOM metadata for a package and its transitive deps.
// Uses free deps BFS traversal (no lockfile).
func CollectSBOMNodesForPackage(ctx context.Context, backend storage.ChecksBackend, packageKey string) ([]SBOMNode, error) {
	bfsResult, err := depscache.MustGet(ctx).CollectFreeDepsWithBFSTraversal(ctx, []string{packageKey})
	if err != nil {
		return nil, fmt.Errorf("collecting deps: %w", err)
	}

	keys := make([]string, 0, len(bfsResult))
	for key := range bfsResult {
		keys = append(keys, key)
	}
	depsMap := bfsMapToDepsMap(bfsResult)

	return batchFetchSBOMNodes(ctx, backend, keys, depsMap)
}

func batchFetchSBOMNodes(ctx context.Context, backend storage.ChecksBackend, ids []string, depsMap map[string][]string) ([]SBOMNode, error) {
	allNodes := make([]SBOMNode, 0, len(ids))

	for i := 0; i < len(ids); i += sbomBatchSize {
		end := min(i+sbomBatchSize, len(ids))
		batch := ids[i:end]

		rows, err := backend.GetBatch(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("fetching SBOM batch %d-%d: %w", i, end, err)
		}

		rowByKey := make(map[string]*storage.ChecksInsertParams, len(rows))
		for _, row := range rows {
			rowByKey[row.Checks.AnalysisIdentifier] = row
		}

		for _, key := range batch {
			node := SBOMNode{Key: key, Deps: depsMap[key]}

			eco, name, version := parseKeyIdentity(key)
			if eco != "" {
				node.Ecosystem = &eco
			}
			if name != "" {
				node.PackageName = &name
			}
			if version != "" {
				node.PackageVersion = &version
			}

			if row, ok := rowByKey[key]; ok {
				node.AnalyzedAt = row.Checks.AnalyzedAt
				node.Violations = extractViolationsFromChecks(row.Checks.Checks)
			}

			allNodes = append(allNodes, node)
		}
	}

	return allNodes, nil
}

// parseKeyIdentity extracts ecosystem, name, and version from an analysis key.
// Handles: "package/{eco}/{name}", "package/{eco}/{name}?version={ver}",
// "package/{eco}/@{scope}/{name}?version={ver}", and "source/..." keys.
func parseKeyIdentity(key string) (ecosystem, name, version string) {
	path, query, hasQuery := strings.Cut(key, "?")
	if hasQuery {
		for param := range strings.SplitSeq(query, "&") {
			if v, ok := strings.CutPrefix(param, "version="); ok {
				version = v
			}
		}
	}

	rest, found := strings.CutPrefix(path, "package/")
	if !found {
		return "", "", ""
	}
	ecosystem, name, found = strings.Cut(rest, "/")
	if !found || ecosystem == "" || name == "" {
		return "", "", ""
	}
	return ecosystem, name, version
}
