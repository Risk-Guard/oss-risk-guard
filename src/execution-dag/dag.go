package executiondag

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"github.com/oss-risk-guard/src/overrides"
	"sync"
)

// mergeable is an internal interface for merging outputs into input
// Not exported - used internally by DAG framework
type mergeable interface {
	Merge(output StatusProvider)
}

type dagNode interface {
	getDependencyKeys() []any
	execute(context.Context, any) (StatusProvider, error)
	read(context.Context, any) (StatusProvider, error, bool)
	storeInContext(context.Context, StatusProvider) context.Context
	createSkippedOutput(reason string, input any) StatusProvider
	allowAutoSkip() bool
	getSupportedOverrides() []overrides.FieldInfo
	GetKind() string
	GetOutput(context.Context) StatusProvider
	GetNodeForReflection() any
}

// nodeEntry stores a node along with its metadata
type nodeEntry[TInput any, TOutput StatusProvider, NodeType Node[TInput, TOutput]] struct {
	node           NodeType
	dependencyKeys []any
}

func (e *nodeEntry[TInput, TOutput, NodeType]) getDependencyKeys() []any {
	return e.dependencyKeys
}

func (e *nodeEntry[TInput, TOutput, NodeType]) allowAutoSkip() bool {
	if skipPropNode, ok := any(e.node).(SkipPropagationNode); ok {
		return skipPropNode.AllowAutoSkip()
	}
	return true // Default: allow auto-skip (backward compatible)
}

func (e *nodeEntry[TInput, TOutput, NodeType]) execute(ctx context.Context, input any) (StatusProvider, error) {
	return e.node.Execute(ctx, input.(TInput))
}

func (e *nodeEntry[TInput, TOutput, NodeType]) read(ctx context.Context, input any) (StatusProvider, error, bool) {
	// Check if node implements ReadableNode
	if readableNode, ok := any(e.node).(ReadableNode[TInput, TOutput]); ok {
		output, err := readableNode.Read(ctx, input.(TInput))
		return output, err, true
	}
	return nil, nil, false
}

func (e *nodeEntry[TInput, TOutput, NodeType]) storeInContext(ctx context.Context, output StatusProvider) context.Context {
	return storeOutputForNode[NodeType, TOutput](ctx, output.(TOutput))
}

func (e *nodeEntry[TInput, TOutput, NodeType]) createSkippedOutput(reason string, input any) StatusProvider {
	return e.node.CreateSkippedOutput(reason, input.(TInput))
}

func (e *nodeEntry[TInput, TOutput, NodeType]) GetKind() string {
	return e.node.Kind()
}

func (e *nodeEntry[TInput, TOutput, NodeType]) GetOutput(ctx context.Context) StatusProvider {
	return GetOutputForNode[NodeType, TOutput](ctx)
}

func (e *nodeEntry[TInput, TOutput, NodeType]) GetNodeForReflection() any {
	return e.node
}

func (e *nodeEntry[TInput, TOutput, NodeType]) getSupportedOverrides() []overrides.FieldInfo {
	var zero TOutput
	ov, ok := any(zero).(OverridableV2)
	if !ok {
		return nil
	}
	return ov.GetSupportedOverrides()
}

type DAG[TInput any] struct {
	nodes map[any]dagNode // typeKey[NodeType]{} -> entry
	mu    sync.RWMutex
}

// NewDAG creates a new empty DAG
func NewDAG[TInput any]() *DAG[TInput] {
	return &DAG[TInput]{
		nodes: make(map[any]dagNode),
	}
}

// AddNode adds a node to the DAG
// Dependencies are extracted from node.GetDependencies() which should return DependsOn[NodeType]() values
// Panics if a node with the same type is already registered
func AddNode[TInput any, TOutput StatusProvider, NodeType Node[TInput, TOutput]](
	dag *DAG[TInput],
	node NodeType,
) {
	key := toTypeKey[NodeType]()

	dag.mu.Lock()
	defer dag.mu.Unlock()

	// Check if this node type already exists
	if _, exists := dag.nodes[key]; exists {
		var zero NodeType
		panic(fmt.Sprintf("execution-dag: node with type %T already registered", zero))
	}

	// Extract dependencies from the node
	dependencyKeys := node.GetDependencies()

	// Create entry
	entry := &nodeEntry[TInput, TOutput, NodeType]{
		node:           node,
		dependencyKeys: dependencyKeys,
	}

	dag.nodes[key] = entry
}

// GetNodes returns all nodes in the DAG
func (d *DAG[TInput]) GetNodes() []dagNode {
	d.mu.RLock()
	defer d.mu.RUnlock()

	nodes := make([]dagNode, 0, len(d.nodes))
	for _, node := range d.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetSupportedOverrides collects override field descriptors from all nodes
// whose output implements OverridableV2.
func (d *DAG[TInput]) GetSupportedOverrides() []overrides.FieldInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var all []overrides.FieldInfo
	for _, node := range d.nodes {
		fields := node.getSupportedOverrides()
		if len(fields) == 0 {
			continue
		}
		nodeType := reflect.TypeOf(node.GetNodeForReflection()).String()
		for i := range fields {
			fields[i].NodeType = nodeType
		}
		all = append(all, fields...)
	}
	return all
}

func (d *DAG[TInput]) CollectUpstreamSources(node any) map[string]Source {
	dn, ok := node.(dagNode)
	if !ok {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	result := make(map[string]Source)
	d.collectSources(dn, make(map[any]bool), result)
	return result
}

func (d *DAG[TInput]) collectSources(node dagNode, visited map[any]bool, result map[string]Source) {
	if sp, ok := node.GetNodeForReflection().(SourceProvider); ok {
		maps.Copy(result, sp.GetSources())
	}
	for _, depKey := range node.getDependencyKeys() {
		if visited[depKey] {
			continue
		}
		visited[depKey] = true
		if depNode, exists := d.nodes[depKey]; exists {
			d.collectSources(depNode, visited, result)
		}
	}
}

func (d *DAG[TInput]) mergeIntoInput(input *TInput, output StatusProvider) {
	// input is already a pointer, use it directly to call Merge
	if m, ok := any(input).(mergeable); ok {
		m.Merge(output)
	}
}
