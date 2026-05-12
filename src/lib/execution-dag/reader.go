package executiondag

import "context"

// ReadableNode is an optional interface that nodes can implement to support
// loading data from disk instead of executing (used with --no-fetch flag).
// Nodes that implement this interface can be loaded from previous runs.
type ReadableNode[TInput any, TOutput StatusProvider] interface {
	Node[TInput, TOutput]
	Read(ctx context.Context, input TInput) (TOutput, error)
}
