package executiondag

import (
	"testing"
)

// TestDAG_Execute_StageParallelism_NoRace puts three sibling nodes (no edges
// between them) in a single stage and asserts all of their outputs are
// retrievable from the returned ctx. Run with `go test -race` to catch the
// closure-capture race the per-stage ctx snapshot fixes.
func TestDAG_Execute_StageParallelism_NoRace(t *testing.T) {
	dag := NewDAG[mockInput]()
	a := &mockNodeA{}
	s1 := &mockSlowNode1{}
	s2 := &mockSlowNode2{}

	AddNode(dag, a)
	AddNode(dag, s1)
	AddNode(dag, s2)

	ctx := testContext()
	out, _, err := dag.Execute(ctx, mockInput{value: "race"})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	gotA, ok := TryGetOutput[*mockNodeA](out)
	if !ok {
		t.Errorf("mockNodeA output missing from returned ctx")
	} else if gotA.(mockProviderA).name != "nodeA" {
		t.Errorf("mockNodeA output corrupted: %+v", gotA)
	}

	gotS1, ok := TryGetOutput[*mockSlowNode1](out)
	if !ok {
		t.Errorf("mockSlowNode1 output missing from returned ctx")
	} else if gotS1.(mockSlowProvider1).name != "slowNode1" {
		t.Errorf("mockSlowNode1 output corrupted: %+v", gotS1)
	}

	gotS2, ok := TryGetOutput[*mockSlowNode2](out)
	if !ok {
		t.Errorf("mockSlowNode2 output missing from returned ctx")
	} else if gotS2.(mockSlowProvider2).name != "slowNode2" {
		t.Errorf("mockSlowNode2 output corrupted: %+v", gotS2)
	}

	if !a.executed || !s1.executed || !s2.executed {
		t.Errorf("not all sibling nodes executed: a=%v s1=%v s2=%v", a.executed, s1.executed, s2.executed)
	}
}
