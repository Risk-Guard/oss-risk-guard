package depscache

import (
	"context"
	"risk-guard/src/models"
	"slices"
	"strings"
	"sync"
	"time"
)

// NewMemoryCache returns a DepsCache backed entirely by in-memory maps.
// Safe for concurrent use. Intended for the local CLI and for tests.
func NewMemoryCache() DepsCache {
	return &memoryCache{
		timestamps: make(map[string]time.Time),
		freeDeps:   make(map[string][]models.Dependency),
		lockfile:   make(map[string][]models.DepsTreeEdge),
	}
}

type memoryCache struct {
	mu         sync.RWMutex
	timestamps map[string]time.Time
	freeDeps   map[string][]models.Dependency
	lockfile   map[string][]models.DepsTreeEdge
}

func (m *memoryCache) SetTimestamp(_ context.Context, key string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.timestamps[key] = t
	return nil
}

func (m *memoryCache) GetTimestampBatch(_ context.Context, keys []string) (map[string]*time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]*time.Time, len(keys))
	for _, k := range keys {
		if t, ok := m.timestamps[k]; ok {
			tCopy := t
			out[k] = &tCopy
		} else {
			out[k] = nil
		}
	}
	return out, nil
}

func (m *memoryCache) DeleteTimestamps(_ context.Context, keys []string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, k := range keys {
		if _, ok := m.timestamps[k]; ok {
			delete(m.timestamps, k)
			n++
		}
	}
	return n, nil
}

func (m *memoryCache) StoreFreeDeps(_ context.Context, key string, deps []models.Dependency) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(deps) == 0 {
		delete(m.freeDeps, key)
		return nil
	}
	stored := make([]models.Dependency, 0, len(deps))
	for _, d := range deps {
		if d.AnalysisIdentifier == "" {
			continue
		}
		stored = append(stored, models.Dependency{
			AnalysisIdentifier: d.AnalysisIdentifier,
			Location:           models.CopyLocation(d.Location),
			Extras:             append([]string(nil), d.Extras...),
			ExtraMarker:        d.ExtraMarker,
			Dev:                d.Dev,
		})
	}
	m.freeDeps[key] = stored
	return nil
}

func (m *memoryCache) StoreSourceLockfileV2(_ context.Context, sourceKey string, edges []models.DepsTreeEdge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(edges) == 0 {
		delete(m.lockfile, sourceKey)
		return nil
	}
	stored := make([]models.DepsTreeEdge, 0, len(edges))
	for _, e := range edges {
		if e.ChildKey == "" {
			continue
		}
		stored = append(stored, models.DepsTreeEdge{
			ParentKey: e.ParentKey,
			ChildKey:  e.ChildKey,
			Ecosystem: e.Ecosystem,
			Dev:       e.Dev,
			Location:  models.CopyLocation(e.Location),
		})
	}
	m.lockfile[sourceKey] = stored
	return nil
}

func (m *memoryCache) GetSourceLockfile(_ context.Context, sourceKey string) ([]models.DepsTreeEdge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	edges, ok := m.lockfile[sourceKey]
	if !ok {
		return nil, nil
	}
	out := make([]models.DepsTreeEdge, len(edges))
	copy(out, edges)
	return out, nil
}

// CollectFreeDepsWithBFSTraversal performs the same breadth-first walk as the
// Valkey implementation: visit each (key, extras) pair at most once, follow the
// stored free deps of each visited key, and respect ExtraMarker gating against
// the parent entry's extras set.
func (m *memoryCache) CollectFreeDepsWithBFSTraversal(_ context.Context, roots []string) (map[string][]models.Dependency, error) {
	if len(roots) == 0 {
		return map[string][]models.Dependency{}, nil
	}

	visited := make(map[string]struct{})
	result := make(map[string][]models.Dependency)
	type entry struct {
		key    string
		extras []string
	}
	queue := make([]entry, 0, len(roots))

	for _, root := range roots {
		vk := bfsVisitedKey(root, nil)
		if _, seen := visited[vk]; !seen {
			visited[vk] = struct{}{}
			queue = append(queue, entry{key: root})
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		stored, ok := m.freeDeps[cur.key]
		if !ok {
			if _, present := result[cur.key]; !present {
				result[cur.key] = nil
			}
			continue
		}

		var deps []models.Dependency
		for _, d := range stored {
			if d.ExtraMarker != nil && !slices.Contains(cur.extras, *d.ExtraMarker) {
				continue
			}
			deps = append(deps, models.Dependency{
				AnalysisIdentifier: d.AnalysisIdentifier,
				Location:           models.CopyLocation(d.Location),
				Extras:             append([]string(nil), d.Extras...),
				ExtraMarker:        d.ExtraMarker,
				Dev:                d.Dev,
			})

			vk := bfsVisitedKey(d.AnalysisIdentifier, d.Extras)
			if _, seen := visited[vk]; !seen {
				visited[vk] = struct{}{}
				queue = append(queue, entry{key: d.AnalysisIdentifier, extras: d.Extras})
			}
		}

		result[cur.key] = appendDistinctDeps(result[cur.key], deps)
	}

	return result, nil
}

func bfsVisitedKey(key string, extras []string) string {
	if len(extras) == 0 {
		return key
	}
	sorted := make([]string, len(extras))
	copy(sorted, extras)
	slices.Sort(sorted)
	return key + "[" + strings.Join(sorted, ",") + "]"
}

func appendDistinctDeps(existing, incoming []models.Dependency) []models.Dependency {
	if len(existing) == 0 {
		return incoming
	}
	seen := make(map[string]struct{}, len(existing))
	for _, d := range existing {
		seen[d.AnalysisIdentifier] = struct{}{}
	}
	out := existing
	for _, d := range incoming {
		if _, ok := seen[d.AnalysisIdentifier]; !ok {
			out = append(out, d)
			seen[d.AnalysisIdentifier] = struct{}{}
		}
	}
	return out
}
