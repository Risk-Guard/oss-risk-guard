package cache

import (
	"context"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	"go.uber.org/zap"
)

func InitializeCacheBackend(ctx context.Context) (context.Context, error) {
	logger := ctxutil.GetLogger(ctx)
	outputDir := runpath.GetOutputDir(ctx)

	logger.Debug("initializing filesystem cache backend",
		zap.String("output_dir", outputDir))

	return SetCacheBackend(ctx, NewFilesystemBackend(outputDir)), nil
}
