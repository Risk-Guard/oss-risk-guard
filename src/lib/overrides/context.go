package overrides

import "context"

type storeKey struct{}

// SetStore adds an override Store to the context.
func SetStore(ctx context.Context, store *Store) context.Context {
	return context.WithValue(ctx, storeKey{}, store)
}

// GetStore retrieves the override Store from the context.
// Returns nil if no store was set.
func GetStore(ctx context.Context) *Store {
	store, _ := ctx.Value(storeKey{}).(*Store)
	return store
}

func GetOverrides(ctx context.Context) []Override {
	store := GetStore(ctx)
	if store == nil {
		return nil
	}
	return store.GetAll()
}
