package overrides

import (
	"context"
	"sync"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"

	"go.uber.org/zap"
)

// FieldInfo describes a single overridable field for catalog/discovery.
type FieldInfo struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description"`
	NodeType    string `json:"node_type,omitempty"`
}

// Override represents a single field override request.
type Override struct {
	Path       string `json:"path"`                 // e.g., "source_url"
	Value      any    `json:"value"`                // replacement value
	Reason     string `json:"reason"`               // E&O audit trail
	Precedence string `json:"precedence,omitempty"` // "force" (default) always sets; "fallback" sets only when no value resolved
}

// AppliedOverride records what was actually changed during execution.
type AppliedOverride struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Store holds overrides and tracks which were applied during execution.
type Store struct {
	mu        sync.RWMutex
	overrides []Override
	applied   []AppliedOverride
}

// NewStore creates a new Store from a list of overrides.
func NewStore(overrides []Override) *Store {
	return &Store{
		overrides: overrides,
		applied:   []AppliedOverride{},
	}
}

// GetAll returns all overrides in the store (original order).
func (s *Store) GetAll() []Override {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Override, len(s.overrides))
	copy(result, s.overrides)
	return result
}

// RecordApplied records an override that was successfully applied.
func (s *Store) RecordApplied(applied AppliedOverride) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied = append(s.applied, applied)
}

// GetApplied returns all overrides that were applied during execution.
func (s *Store) GetApplied() []AppliedOverride {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]AppliedOverride, len(s.applied))
	copy(result, s.applied)
	return result
}

// WarnUnconsumed logs a warning for any overrides that were not applied by any node.
func (s *Store) WarnUnconsumed(ctx context.Context) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	appliedPaths := make(map[string]bool, len(s.applied))
	for _, a := range s.applied {
		appliedPaths[a.Path] = true
	}

	log := ctxutil.GetLogger(ctx)
	for _, o := range s.overrides {
		if appliedPaths[o.Path] {
			continue
		}
		// A "fallback" override is a gap-filler: it intentionally does nothing
		// when a value was already resolved, so an unapplied fallback is the
		// expected outcome, not a misconfiguration. Only force/default overrides
		// warn when unapplied, where a no-op usually means a wrong path.
		if o.Precedence == "fallback" {
			continue
		}
		log.Warn("override was not applied by any node", zap.String("path", o.Path), zap.String("reason", o.Reason))
	}
}
