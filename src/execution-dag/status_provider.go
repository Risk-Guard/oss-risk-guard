package executiondag

import "github.com/Risk-Guard/oss-risk-guard/src/overrides"

// StatusProvider is an interface that all node outputs must implement.
type StatusProvider interface {
	GetStatus() Status
	GetStatusReason() string
}

// Persistable is implemented by outputs that should be persisted to disk.
// The framework serializes the entire output using PersistKey() as the filename.
type Persistable interface {
	PersistKey() string
}

// OverridableV2 is implemented by outputs that support typed override application.
// Combining apply + describe on the same type ensures compile-time consistency:
// you cannot implement one without the other.
type OverridableV2 interface {
	ApplyOverridesV2([]overrides.Override) ([]overrides.AppliedOverride, error)
	GetSupportedOverrides() []overrides.FieldInfo
}

// Entry represents a single output item for storage.
// Used internally by CollectEntries and storage backends.
type Entry struct {
	Key       string
	Data      any
	Extension string
}
