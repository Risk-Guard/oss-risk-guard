package lockfile

import (
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"testing"
)

func TestPropagateDevFlag_ClearsDevWhenProdReachable(t *testing.T) {
	// C is reachable via prod root A, so all edges pointing to C
	// should have Dev=false after propagation — even the edge from
	// dev-only parent B that arrived with Dev=true from the parser.
	//
	//   root -> A (prod)
	//   root -> B (dev)
	//   A -> C
	//   B -> C (Dev=true from parser)
	//
	edges := []models.DepsTreeEdge{
		{ParentKey: "root", ChildKey: "A", Dev: false},
		{ParentKey: "root", ChildKey: "B", Dev: true},
		{ParentKey: "A", ChildKey: "C", Dev: false},
		{ParentKey: "B", ChildKey: "C", Dev: true},
	}

	PropagateDevFlag(edges, "root")

	expected := map[string]bool{
		"A": false, // prod root
		"B": true,  // only reachable via dev root
		"C": false, // reachable via prod root A
	}

	for i, e := range edges {
		want, ok := expected[e.ChildKey]
		if !ok {
			t.Fatalf("unexpected ChildKey %q at index %d", e.ChildKey, i)
		}
		if e.Dev != want {
			t.Errorf("edge[%d] (%s->%s): Dev=%v, want %v",
				i, e.ParentKey, e.ChildKey, e.Dev, want)
		}
	}
}
