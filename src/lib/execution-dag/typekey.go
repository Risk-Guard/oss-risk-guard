package executiondag

// typeKey is a zero-sized type used as a unique key for each type T
// Each instantiation typeKey[T] creates a unique comparable type
// Used for:
// - Context keys (GetOutput)
// - DAG node keys (internal)
// - Dependency declarations (DependsOn)
type typeKey[T any] struct{}

// DependsOn creates a dependency key for a specific node type
// Usage: func (n *MyNode) GetDependencies() []any { return []any{DependsOn[*jsdeps.Node](), DependsOn[*pydeps.Node]()} }
func DependsOn[NodeType any]() any {
	return typeKey[NodeType]{}
}

func toTypeKey[T any]() any {
	return typeKey[T]{}
}
