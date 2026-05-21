package depscache

import (
	"context"
	"risk-guard/src/models"
	"testing"
	"time"
)

func TestMemoryCache_LockfileRoundTrip(t *testing.T) {
	c := NewMemoryCache()
	ctx := context.Background()
	src := "source/github.com/example/repo"

	edges := []models.DepsTreeEdge{
		{ParentKey: src, ChildKey: "package/npm/a", Ecosystem: "npm"},
		{ParentKey: src, ChildKey: "package/npm/b", Ecosystem: "npm", Dev: true},
		{ParentKey: "", ChildKey: "", Ecosystem: "npm"},
	}

	if err := c.StoreSourceLockfileV2(ctx, src, edges); err != nil {
		t.Fatalf("store: %v", err)
	}

	got, err := c.GetSourceLockfile(ctx, src)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 edges (empty child filtered), got %d", len(got))
	}

	missing, err := c.GetSourceLockfile(ctx, "source/github.com/other/repo")
	if err != nil {
		t.Fatalf("get missing: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil for missing source, got %v", missing)
	}
}

func TestMemoryCache_LockfileEmptyClears(t *testing.T) {
	c := NewMemoryCache()
	ctx := context.Background()
	src := "source/x"

	_ = c.StoreSourceLockfileV2(ctx, src, []models.DepsTreeEdge{{ChildKey: "package/npm/a"}})
	if err := c.StoreSourceLockfileV2(ctx, src, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got, _ := c.GetSourceLockfile(ctx, src)
	if got != nil {
		t.Errorf("expected nil after clear, got %v", got)
	}
}

func TestMemoryCache_BFSSimpleGraph(t *testing.T) {
	c := NewMemoryCache()
	ctx := context.Background()

	// root -> a, c
	// a    -> b
	// b    -> (none)
	// c    -> (none)
	_ = c.StoreFreeDeps(ctx, "root", []models.Dependency{
		{AnalysisIdentifier: "a"}, {AnalysisIdentifier: "c"},
	})
	_ = c.StoreFreeDeps(ctx, "a", []models.Dependency{{AnalysisIdentifier: "b"}})

	out, err := c.CollectFreeDepsWithBFSTraversal(ctx, []string{"root"})
	if err != nil {
		t.Fatalf("bfs: %v", err)
	}

	if len(out["root"]) != 2 {
		t.Errorf("expected root to have 2 deps, got %d", len(out["root"]))
	}
	if len(out["a"]) != 1 || out["a"][0].AnalysisIdentifier != "b" {
		t.Errorf("expected a -> [b], got %v", out["a"])
	}
	if _, ok := out["b"]; !ok {
		t.Errorf("expected b to be visited (with nil deps)")
	}
	if _, ok := out["c"]; !ok {
		t.Errorf("expected c to be visited (with nil deps)")
	}
}

func TestMemoryCache_BFSCycle(t *testing.T) {
	c := NewMemoryCache()
	ctx := context.Background()

	_ = c.StoreFreeDeps(ctx, "a", []models.Dependency{{AnalysisIdentifier: "b"}})
	_ = c.StoreFreeDeps(ctx, "b", []models.Dependency{{AnalysisIdentifier: "a"}})

	done := make(chan struct{})
	var out map[string][]models.Dependency
	var err error
	go func() {
		out, err = c.CollectFreeDepsWithBFSTraversal(ctx, []string{"a"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("BFS did not terminate on cycle")
	}
	if err != nil {
		t.Fatalf("bfs: %v", err)
	}
	if len(out["a"]) != 1 || len(out["b"]) != 1 {
		t.Errorf("expected cycle to be walked once each, got a=%v b=%v", out["a"], out["b"])
	}
}

func TestMemoryCache_BFSEmptyRoots(t *testing.T) {
	c := NewMemoryCache()
	out, err := c.CollectFreeDepsWithBFSTraversal(context.Background(), nil)
	if err != nil {
		t.Fatalf("bfs: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty result, got %v", out)
	}
}

func TestMemoryCache_BFSExtraMarkerGates(t *testing.T) {
	c := NewMemoryCache()
	ctx := context.Background()

	devMarker := "dev"
	// root -> a (gated by extras[dev]), b (always)
	_ = c.StoreFreeDeps(ctx, "root", []models.Dependency{
		{AnalysisIdentifier: "a", ExtraMarker: &devMarker},
		{AnalysisIdentifier: "b"},
	})

	out, _ := c.CollectFreeDepsWithBFSTraversal(ctx, []string{"root"})
	if len(out["root"]) != 1 || out["root"][0].AnalysisIdentifier != "b" {
		t.Errorf("expected gated marker to drop a; got %v", out["root"])
	}
}

func TestMemoryCache_Timestamps(t *testing.T) {
	c := NewMemoryCache()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if err := c.SetTimestamp(ctx, "k1", now); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := c.GetTimestampBatch(ctx, []string{"k1", "k2"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got["k1"] == nil || !got["k1"].Equal(now) {
		t.Errorf("k1: expected %v, got %v", now, got["k1"])
	}
	if got["k2"] != nil {
		t.Errorf("k2: expected nil, got %v", got["k2"])
	}

	n, err := c.DeleteTimestamps(ctx, []string{"k1", "k2"})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 deletion, got %d", n)
	}
}
