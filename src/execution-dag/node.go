package executiondag

import "context"

// Node represents a node in the execution DAG
// TInput is the type of the input data passed to all nodes
// TOutput is the type of the output data produced by this node (must implement StatusProvider)
type Node[TInput any, TOutput StatusProvider] interface {
	// Execute runs the node's logic
	// - ctx: context for cancellation, logging, and accessing previous node outputs via GetOutput
	// - input: the input data for the node. MUST be treated as read-only. The
	//   DAG runs sibling nodes in a stage in parallel and passes the same input
	//   by value to each; if input contains pointer or slice fields, mutating
	//   them from inside Execute will race against other workers in the stage.
	// Returns the node's output or an error
	// If output.GetStatus() == StatusSkipped, dependent nodes are auto-skipped
	// (unless they implement SkipPropagationNode with AllowAutoSkip() returning false)
	// Any error halts the entire DAG execution
	Execute(ctx context.Context, input TInput) (TOutput, error)

	// GetDependencies returns the dependency keys for this node
	// Use DependsOn[T]() to create dependency keys
	GetDependencies() []any

	// CreateSkippedOutput creates a skipped output with the given reason
	// Called by the DAG framework when this node is auto-skipped due to a dependency being skipped
	// The implementation should return an output with StatusSkipped and appropriate zero/nil values for fields
	CreateSkippedOutput(reason string, input TInput) TOutput

	// Kind returns the kind/category of this node (e.g., "transformer", "scanner", "check")
	Kind() string
}

// SkipPropagationNode is an optional interface that nodes can implement
// to control whether they are automatically skipped when dependencies are skipped.
// By default, if a node's dependency is skipped, the node is auto-skipped.
// Implementing this interface allows nodes to opt-out of this behavior.
type SkipPropagationNode interface {
	// AllowAutoSkip returns whether this node should be automatically skipped
	// when one or more of its dependencies are skipped.
	// - Return true: node will be auto-skipped (default behavior)
	// - Return false: node's Execute() will be called, allowing it to inspect dependency status
	AllowAutoSkip() bool
}
