package depsgraph

import (
	"fmt"
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func edge(parent, child string) DepsTreeEdge {
	return DepsTreeEdge{
		DepsTreeEdge: models.DepsTreeEdge{
			ParentKey: parent,
			ChildKey:  child,
		},
	}
}

func TestIndexDependencyPaths_SimpleTree(t *testing.T) {
	// root -> A -> B
	roots := []string{"root"}
	edges := []DepsTreeEdge{
		edge("root", "A"),
		edge("A", "B"),
	}

	result := IndexDependencyPaths(roots, edges)

	require.Contains(t, result, "root")
	assert.Equal(t, []string{}, result["root"].Path)

	require.Contains(t, result, "A")
	assert.Equal(t, []string{"root"}, result["A"].Path)

	require.Contains(t, result, "B")
	assert.Equal(t, []string{"root", "A"}, result["B"].Path)
}

func TestIndexDependencyPaths_CyclicEdges(t *testing.T) {
	// root -> A -> B -> A (cycle between A and B)
	roots := []string{"root"}
	edges := []DepsTreeEdge{
		edge("root", "A"),
		edge("A", "B"),
		edge("B", "A"),
	}

	done := make(chan struct{})
	go func() {
		IndexDependencyPaths(roots, edges)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("IndexDependencyPaths hung on cyclic edges")
	}
}

func TestIndexDependencyPaths_SelfLoop(t *testing.T) {
	// root -> A, and A -> A (self-referential)
	roots := []string{"root"}
	edges := []DepsTreeEdge{
		edge("root", "A"),
		edge("A", "A"),
	}

	done := make(chan struct{})
	go func() {
		IndexDependencyPaths(roots, edges)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("IndexDependencyPaths hung on self-loop edge")
	}
}

func TestIndexDependencyPaths_DeepChain(t *testing.T) {
	// root -> n0 -> n1 -> ... -> n499
	roots := []string{"root"}
	depth := 500
	edges := make([]DepsTreeEdge, depth)
	edges[0] = edge("root", "n0")
	for i := 1; i < depth; i++ {
		edges[i] = edge(fmt.Sprintf("n%d", i-1), fmt.Sprintf("n%d", i))
	}

	result := IndexDependencyPaths(roots, edges)

	// Leaf node should have full path from root
	leafKey := fmt.Sprintf("n%d", depth-1)
	require.Contains(t, result, leafKey)

	expectedPath := make([]string, depth)
	expectedPath[0] = "root"
	for i := 1; i < depth; i++ {
		expectedPath[i] = fmt.Sprintf("n%d", i-1)
	}
	assert.Equal(t, expectedPath, result[leafKey].Path)
}

func TestIndexDependencyPaths_DevFlag(t *testing.T) {
	roots := []string{"root"}
	edges := []DepsTreeEdge{
		edge("root", "A"),
		devEdge("root", "B"),
		edge("A", "C"),
		edge("B", "D"),
	}

	result := IndexDependencyPaths(roots, edges)

	assert.False(t, result["A"].Dev, "prod edge should have Dev=false")
	assert.True(t, result["B"].Dev, "dev edge should have Dev=true")
	assert.False(t, result["C"].Dev, "transitive of prod edge should have Dev=false")
	assert.True(t, result["D"].Dev, "transitive of dev edge should have Dev=true")
}
