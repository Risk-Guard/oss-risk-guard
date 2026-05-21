package cache

import "context"

type cacheBackendKey struct{}

func SetCacheBackend(ctx context.Context, backend Backend) context.Context {
	return context.WithValue(ctx, cacheBackendKey{}, backend)
}

func GetCacheBackend(ctx context.Context) Backend {
	backend := ctx.Value(cacheBackendKey{})
	if backend == nil {
		panic("cache backend not found in context - ensure cache backend is initialized in root command")
	}
	return backend.(Backend)
}
