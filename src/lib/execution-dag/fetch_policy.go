package executiondag

import "context"

type noFetchKey struct{}

// WithNoFetch returns a context whose value signals that fetch nodes should
// read previously persisted output instead of executing.
func WithNoFetch(ctx context.Context, noFetch bool) context.Context {
	return context.WithValue(ctx, noFetchKey{}, noFetch)
}

// IsNoFetch reports whether the context carries the no-fetch signal.
func IsNoFetch(ctx context.Context) bool {
	b, _ := ctx.Value(noFetchKey{}).(bool)
	return b
}
