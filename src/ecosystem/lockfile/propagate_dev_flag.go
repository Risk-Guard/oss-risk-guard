package lockfile

import "github.com/Risk-Guard/oss-risk-guard/src/models"

// PropagateDevFlag marks edges as Dev when their ChildKey is only reachable
// through dev root edges. Root edges are identified by ParentKey == rootKey.
func PropagateDevFlag(edges []models.DepsTreeEdge, rootKey string) {
	prodRoots := make(map[string]struct{})
	adjacency := make(map[string][]string)

	for _, e := range edges {
		if e.ParentKey == rootKey && !e.Dev {
			prodRoots[e.ChildKey] = struct{}{}
		}
		if e.ParentKey != rootKey {
			adjacency[e.ParentKey] = append(adjacency[e.ParentKey], e.ChildKey)
		}
	}

	prodReachable := make(map[string]struct{})
	queue := make([]string, 0, len(prodRoots))
	for k := range prodRoots {
		queue = append(queue, k)
		prodReachable[k] = struct{}{}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, child := range adjacency[cur] {
			if _, seen := prodReachable[child]; !seen {
				prodReachable[child] = struct{}{}
				queue = append(queue, child)
			}
		}
	}

	for i := range edges {
		_, prod := prodReachable[edges[i].ChildKey]
		edges[i].Dev = !prod
	}
}
