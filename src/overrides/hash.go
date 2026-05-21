package overrides

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

type overrideWithKey struct {
	override Override
	valueKey string
}

// Hash computes a stable hash of overrides for cache keying.
// Returns empty string and nil error if no overrides.
func Hash(overrides []Override) (string, error) {
	if len(overrides) == 0 {
		return "", nil
	}

	// Pre-compute marshaled values to avoid error handling inside sort
	items := make([]overrideWithKey, len(overrides))
	for i, o := range overrides {
		valueBytes, err := json.Marshal(o.Value)
		if err != nil {
			return "", fmt.Errorf("failed to marshal override value at path %q: %w", o.Path, err)
		}
		items[i] = overrideWithKey{override: o, valueKey: string(valueBytes)}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].override.Path != items[j].override.Path {
			return items[i].override.Path < items[j].override.Path
		}
		if items[i].valueKey != items[j].valueKey {
			return items[i].valueKey < items[j].valueKey
		}
		return items[i].override.Reason < items[j].override.Reason
	})

	sorted := make([]Override, len(items))
	for i, item := range items {
		sorted[i] = item.override
	}

	data, err := json.Marshal(sorted)
	if err != nil {
		return "", fmt.Errorf("failed to marshal overrides: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16]), nil
}
