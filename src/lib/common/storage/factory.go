package storage

import "context"

func InitializeStorageBackend(ctx context.Context) (context.Context, error) {
	return SetStorageBackend(ctx, NewFileBackend()), nil
}
