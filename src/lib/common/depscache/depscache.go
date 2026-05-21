package depscache

import (
	"context"
	"risk-guard/src/models"
	"time"
)

type DepsCache interface {
	SetTimestamp(ctx context.Context, key string, t time.Time) error
	GetTimestampBatch(ctx context.Context, keys []string) (map[string]*time.Time, error)
	DeleteTimestamps(ctx context.Context, keys []string) (int64, error)
	StoreFreeDeps(ctx context.Context, key string, deps []models.Dependency) error
	CollectFreeDepsWithBFSTraversal(ctx context.Context, roots []string) (map[string][]models.Dependency, error)
	StoreSourceLockfileV2(ctx context.Context, sourceKey string, edges []models.DepsTreeEdge) error
	GetSourceLockfile(ctx context.Context, sourceKey string) ([]models.DepsTreeEdge, error)
}

type depsCacheKey struct{}

func Set(ctx context.Context, c DepsCache) context.Context {
	return context.WithValue(ctx, depsCacheKey{}, c)
}

func Get(ctx context.Context) DepsCache {
	c, _ := ctx.Value(depsCacheKey{}).(DepsCache)
	return c
}

func MustGet(ctx context.Context) DepsCache {
	c := Get(ctx)
	if c == nil {
		panic("deps cache not found in context - ensure deps cache is initialized in root command")
	}
	return c
}
