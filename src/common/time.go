package common

import (
	"fmt"
	"time"
)

// ParseRegistryTimestamp parses timestamps from package registries (NPM, etc.)
// that may include fractional seconds. Tries RFC3339Nano first (superset that
// handles fractional seconds), then falls back to RFC3339.
func ParseRegistryTimestamp(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	t, err := time.Parse(time.RFC3339Nano, dateStr)
	if err == nil {
		return t, nil
	}
	t, err = time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("registry returned unparseable timestamp %q: %w", dateStr, err)
	}
	return t, nil
}
