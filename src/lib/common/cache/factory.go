package cache

import (
	"context"
	"risk-guard/src/ctxutil"
	"risk-guard/src/runpath"

	"go.uber.org/zap"
)

func InitializeCacheBackend(ctx context.Context) (context.Context, error) {
	logger := ctxutil.GetLogger(ctx)
	outputDir := runpath.GetOutputDir(ctx)

	logger.Debug("initializing filesystem cache backend",
		zap.String("output_dir", outputDir))

	return SetCacheBackend(ctx, NewFilesystemBackend(outputDir)), nil
}
