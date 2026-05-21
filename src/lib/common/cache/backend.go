package cache

import (
	"context"
	"time"
)

// Backend defines the interface for cache storage implementations.
// Implementations can be filesystem-based, database-based (BigQuery), or any other storage system.
type Backend interface {
	// Get retrieves cached data for the given key.
	// Returns the data and the timestamp when it was stored.
	// Returns nil data if the key doesn't exist or has expired.
	// Returns error only for actual storage failures (not for cache misses).
	Get(ctx context.Context, key string, maxAge time.Duration) (data []byte, storedAt time.Time, err error)

	// Set stores data in the cache with the given key.
	// The backend should record the current timestamp for expiry checking.
	// url is the original request URL (for visibility/debugging).
	Set(ctx context.Context, key string, data []byte) error

	// Close closes the backend and releases any resources.
	// After Close is called, the backend should not be used.
	Close() error
}
