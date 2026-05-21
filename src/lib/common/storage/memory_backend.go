package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// NewMemoryBackend returns a Backend whose Checks() is an in-memory map and
// whose Metadata() is a no-op. Safe for concurrent use. Intended for the local
// CLI's SBOM path and for tests of code that reads ChecksBackend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		metadata: &noOpMetadataBackend{},
		checks: &memoryChecksBackend{
			rows: make(map[string]ChecksInsertParams),
		},
	}
}

type MemoryBackend struct {
	metadata *noOpMetadataBackend
	checks   *memoryChecksBackend
}

func (m *MemoryBackend) Metadata() MetadataBackend { return m.metadata }
func (m *MemoryBackend) Checks() ChecksBackend     { return m.checks }

type memoryChecksBackend struct {
	mu   sync.RWMutex
	rows map[string]ChecksInsertParams
}

func (m *memoryChecksBackend) Get(_ context.Context, analysisID string) (*ChecksInsertParams, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	row, ok := m.rows[analysisID]
	if !ok {
		return nil, nil
	}
	rowCopy := row
	return &rowCopy, nil
}

func (m *memoryChecksBackend) Exists(_ context.Context, analysisID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.rows[analysisID]
	return ok, nil
}

func (m *memoryChecksBackend) Insert(_ context.Context, params ChecksInsertParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[params.Checks.AnalysisIdentifier] = params
	return nil
}

func (m *memoryChecksBackend) GetBatch(_ context.Context, analysisIDs []string) ([]*ChecksInsertParams, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*ChecksInsertParams, 0, len(analysisIDs))
	for _, id := range analysisIDs {
		row, ok := m.rows[id]
		if !ok {
			continue
		}
		rowCopy := row
		out = append(out, &rowCopy)
	}
	return out, nil
}

// GetPolicy returns the stored PolicyData as JSON, matching GCSChecksBackend.
// policy.Evaluate consumes this by json.Unmarshal into its internal storedPolicy
// struct ({policy, raw_yaml, error}); returning only RawYAML would cause it to
// fail with "parsing stored policy".
func (m *memoryChecksBackend) GetPolicy(_ context.Context, analysisID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	row, ok := m.rows[analysisID]
	if !ok || row.Policy == nil {
		return "", nil
	}
	data, err := json.Marshal(row.Policy)
	if err != nil {
		return "", fmt.Errorf("marshaling policy: %w", err)
	}
	return string(data), nil
}
