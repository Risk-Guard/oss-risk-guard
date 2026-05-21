package depsgraph

func IndexDependencyPaths(roots []string, edges []DepsTreeEdge) map[string]PathInfo {
	rootSet := make(map[string]bool, len(roots))
	for _, r := range roots {
		rootSet[r] = true
	}

	edgeByChild := make(map[string]DepsTreeEdge, len(edges))
	for _, e := range edges {
		edgeByChild[e.ChildKey] = e
	}

	result := make(map[string]PathInfo, len(edges)+len(roots))

	for _, root := range roots {
		result[root] = PathInfo{
			Path: []string{},
		}
	}

	for _, edge := range edges {
		path, rootEdge := resolveDependencyPath(edge.ChildKey, edgeByChild, rootSet)
		result[edge.ChildKey] = PathInfo{
			Path:         path,
			RootLocation: rootEdge.Location,
			Dev:          rootEdge.Dev,
		}
	}

	return result
}

func resolveDependencyPath(key string, edgeByChild map[string]DepsTreeEdge, rootSet map[string]bool) ([]string, DepsTreeEdge) {
	var path []string
	var firstHopEdge DepsTreeEdge

	visited := make(map[string]bool, len(edgeByChild))
	current := key
	for range len(edgeByChild) {
		if visited[current] {
			break
		}
		visited[current] = true

		edge, exists := edgeByChild[current]
		if !exists {
			break
		}

		if rootSet[edge.ParentKey] {
			path = append([]string{edge.ParentKey}, path...)
			firstHopEdge = edge
			break
		}

		path = append([]string{edge.ParentKey}, path...)
		firstHopEdge = edge
		current = edge.ParentKey
	}

	return path, firstHopEdge
}
