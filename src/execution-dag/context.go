package executiondag

import (
	"context"
	"fmt"
)

// GetOutput retrieves the output of a node by its node type from the context.
// The context must be the one returned by DAG.Execute(), as it contains all node outputs.
// Panics if the node type is not found in the context.
// Usage: GetOutput[*jsdeps.Node](ctx)
func GetOutput[NodeType any](ctx context.Context) any {
	value := ctx.Value(typeKey[NodeType]{})
	if value == nil {
		var zero NodeType
		panic(fmt.Sprintf("execution-dag: output for node type %T not found in context", zero))
	}
	return value
}

// GetOutputForNode is an internal helper that retrieves output with proper typing.
// Used by nodeEntry.GetOutput() to maintain type safety.
func GetOutputForNode[NodeType any, TOutput StatusProvider](ctx context.Context) TOutput {
	value := ctx.Value(typeKey[NodeType]{})
	if value == nil {
		var zero NodeType
		panic(fmt.Sprintf("execution-dag: output for node type %T not found in context", zero))
	}
	return value.(TOutput)
}

// TryGetOutput retrieves the output of a node by its node type from the context.
// The context must be the one returned by DAG.Execute(), as it contains all node outputs.
// Returns the output and true if found, nil and false if not found.
func TryGetOutput[NodeType any](ctx context.Context) (any, bool) {
	value := ctx.Value(typeKey[NodeType]{})
	if value == nil {
		return nil, false
	}
	return value, true
}

// storeOutputForNode stores an output in the context by its node type
func storeOutputForNode[NodeType any, TOutput StatusProvider](ctx context.Context, output TOutput) context.Context {
	return context.WithValue(ctx, typeKey[NodeType]{}, output)
}
