package cache

import (
	"context"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	"go.uber.org/zap"
)

func InitializeCacheBackend(ctx context.Context) (context.Context, error) {
	logger := ctxutil.GetLogger(ctx)
	dir := runpath.GetNetworkCacheDir(ctx)

	logger.Debug("initializing filesystem cache backend",
		zap.String("dir", dir))

	return SetCacheBackend(ctx, NewFilesystemBackend(dir)), nil
}
