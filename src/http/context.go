package http

import (
	"context"

	"github.com/avast/retry-go/v4"
)

type retryOptionsKey struct{}

// SetRetryOptions stores retry options in context for use by HTTP clients.
// Used by tests to configure fast retry settings (see client_test.go setupTestContext).
// Note: deadcode tool reports this as unreachable but it's called from test code.
func SetRetryOptions(ctx context.Context, opts []retry.Option) context.Context {
	return context.WithValue(ctx, retryOptionsKey{}, opts)
}

func GetRetryOptions(ctx context.Context) ([]retry.Option, bool) {
	opts := ctx.Value(retryOptionsKey{})
	if opts == nil {
		var zero []retry.Option
		return zero, false
	}
	return opts.([]retry.Option), true
}
