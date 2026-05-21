package executiondag

import "fmt"

// topologicalSort returns nodes grouped by execution stage (parallel execution within each stage)
func (d *DAG[TInput]) topologicalSort() ([][]any, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Calculate in-degree for each node
	inDegree := make(map[any]int)
	for key := range d.nodes {
		inDegree[key] = 0
	}

	// Verify all dependencies exist and calculate in-degrees
	for key, entry := range d.nodes {
		deps := entry.getDependencyKeys()

		for _, depKey := range deps {
			if _, exists := d.nodes[depKey]; !exists {
				return nil, fmt.Errorf("node with key %v depends on %v which is not in the DAG", key, depKey)
			}
		}
		inDegree[key] = len(deps)
	}

	var stages [][]any
	remaining := len(d.nodes)

	for remaining > 0 {
		// Find all nodes with in-degree 0 (can be executed in parallel)
		var stage []any
		for key, degree := range inDegree {
			if degree == 0 {
				stage = append(stage, key)
			}
		}

		if len(stage) == 0 {
			return nil, fmt.Errorf("cycle detected in DAG")
		}

		stages = append(stages, stage)

		// Remove these nodes from the graph
		for _, key := range stage {
			delete(inDegree, key)
			remaining--

			// Reduce in-degree of dependent nodes
			for dependentKey, entry := range d.nodes {
				deps := entry.getDependencyKeys()

				for _, depKey := range deps {
					if depKey == key {
						inDegree[dependentKey]--
					}
				}
			}
		}
	}

	return stages, nil
}
