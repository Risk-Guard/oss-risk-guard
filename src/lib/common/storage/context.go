package storage

import "context"

type traceIDKey struct{}

func SetTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey{}, traceID)
}

func GetTraceID(ctx context.Context) string {
	id, _ := ctx.Value(traceIDKey{}).(string)
	return id
}

type storageBackendKey struct{}

func SetStorageBackend(ctx context.Context, backend Backend) context.Context {
	return context.WithValue(ctx, storageBackendKey{}, backend)
}

func MustGetBackend(ctx context.Context) Backend {
	backend := ctx.Value(storageBackendKey{})
	if backend == nil {
		panic("storage backend not found in context - ensure storage backend is initialized in root command")
	}
	return backend.(Backend)
}
