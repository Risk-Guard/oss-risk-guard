package dag_builder

import (
	"context"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
)

// CollectEntries collects entries from executed nodes in the DAG.
// For outputs implementing Persistable, creates an Entry with PersistKey() as key
// and the output itself as data.
// In write-fetch-only mode, only collects entries from fetch nodes.
func CollectEntries(ctx context.Context, dag *executiondag.DAG[dag_impl.Input], input dag_impl.Input) []executiondag.Entry {
	writeFetchOnly := input.WriteFetchOnly
	var entries []executiondag.Entry

	nodes := dag.GetNodes()
	for _, node := range nodes {
		if writeFetchOnly && node.GetKind() != "fetch" {
			continue
		}

		output := node.GetOutput(ctx)
		if output == nil {
			continue
		}

		if p, ok := output.(executiondag.Persistable); ok {
			entries = append(entries, executiondag.Entry{
				Key:  p.PersistKey(),
				Data: output,
			})
		}
	}

	return entries
}
