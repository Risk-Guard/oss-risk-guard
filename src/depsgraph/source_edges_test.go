package depsgraph

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/stretchr/testify/assert"
)

func devEdge(parent, child string) DepsTreeEdge {
	return DepsTreeEdge{
		DepsTreeEdge: models.DepsTreeEdge{
			ParentKey: parent,
			ChildKey:  child,
			Dev:       true,
		},
	}
}

func TestPropagateFreeDevFlag_BasicDevTransitive(t *testing.T) {
	// source -> pytest (dev), pytest -> pluggy
	// pluggy should become dev since it's only reachable through a dev root
	src := "source/github.com/example/repo"
	edges := []DepsTreeEdge{
		devEdge(src, "package/pypi/pytest"),
		edge("package/pypi/pytest", "package/pypi/pluggy"),
	}

	propagateDevFlagForEdges(edges, src)

	assert.True(t, edges[0].Dev, "pytest direct dev dep")
	assert.True(t, edges[1].Dev, "pluggy transitive through dev root")
}

func TestPropagateFreeDevFlag_ProdUnaffected(t *testing.T) {
	// source -> requests (prod), requests -> certifi
	// neither should be marked dev
	src := "source/github.com/example/repo"
	edges := []DepsTreeEdge{
		edge(src, "package/pypi/requests"),
		edge("package/pypi/requests", "package/pypi/certifi"),
	}

	propagateDevFlagForEdges(edges, src)

	assert.False(t, edges[0].Dev, "requests is prod")
	assert.False(t, edges[1].Dev, "certifi is transitive prod")
}

func TestPropagateFreeDevFlag_MixedPaths(t *testing.T) {
	// source -> requests (prod), source -> pytest (dev)
	// requests -> urllib3, pytest -> urllib3
	// urllib3 is reachable from prod, so it stays non-dev
	src := "source/github.com/example/repo"
	edges := []DepsTreeEdge{
		edge(src, "package/pypi/requests"),
		devEdge(src, "package/pypi/pytest"),
		edge("package/pypi/requests", "package/pypi/urllib3"),
		edge("package/pypi/pytest", "package/pypi/urllib3"),
	}

	propagateDevFlagForEdges(edges, src)

	assert.False(t, edges[0].Dev, "requests is prod")
	assert.True(t, edges[1].Dev, "pytest is dev")
	assert.False(t, edges[2].Dev, "urllib3 reachable from prod")
	assert.False(t, edges[3].Dev, "urllib3 reachable from prod (via pytest edge)")
}

func TestPropagateFreeDevFlag_AllDevRoots(t *testing.T) {
	// source -> pytest (dev), source -> ruff (dev)
	// pytest -> pluggy, ruff -> tomli
	// everything should be dev
	src := "source/github.com/example/repo"
	edges := []DepsTreeEdge{
		devEdge(src, "package/pypi/pytest"),
		devEdge(src, "package/pypi/ruff"),
		edge("package/pypi/pytest", "package/pypi/pluggy"),
		edge("package/pypi/ruff", "package/pypi/tomli"),
	}

	propagateDevFlagForEdges(edges, src)

	for i, e := range edges {
		assert.True(t, e.Dev, "edge %d (%s -> %s) should be dev", i, e.ParentKey, e.ChildKey)
	}
}

func TestPropagateFreeDevFlag_EmptyEdges(t *testing.T) {
	propagateDevFlagForEdges(nil, "source/github.com/example/repo")
	propagateDevFlagForEdges([]DepsTreeEdge{}, "source/github.com/example/repo")
}

func TestPropagateFreeDevFlag_DeepDevChain(t *testing.T) {
	// source -> pytest (dev) -> pluggy -> iniconfig
	// all transitive deps should be marked dev
	src := "source/github.com/example/repo"
	edges := []DepsTreeEdge{
		devEdge(src, "package/pypi/pytest"),
		edge("package/pypi/pytest", "package/pypi/pluggy"),
		edge("package/pypi/pluggy", "package/pypi/iniconfig"),
	}

	propagateDevFlagForEdges(edges, src)

	assert.True(t, edges[0].Dev)
	assert.True(t, edges[1].Dev)
	assert.True(t, edges[2].Dev)
}
