// Package ctxutil provides context helpers for logger and source token only.
// DO NOT add new context helpers here - it causes import cycles.
// Other packages should define their own context helpers (see src/overrides/context.go).
package ctxutil

import (
	"context"
	"os"

	"go.uber.org/zap"
)

type loggerKey struct{}

func SetLogger(ctx context.Context, logger *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// Panics if no logger is found - this enforces proper initialization.
func GetLogger(ctx context.Context) *zap.Logger {
	logger, ok := ctx.Value(loggerKey{}).(*zap.Logger)
	if !ok || logger == nil {
		panic("logger not found in context - ensure logger is initialized in root command")
	}
	return logger
}

type sourceTokenKey struct{}

func SetSourceToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, sourceTokenKey{}, token)
}

func GetSourceToken(ctx context.Context) string {
	token, _ := ctx.Value(sourceTokenKey{}).(string)
	return token
}

type tempDirKey struct{}

func SetTempDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, tempDirKey{}, dir)
}

func GetTempDir(ctx context.Context) string {
	if dir, ok := ctx.Value(tempDirKey{}).(string); ok {
		return dir
	}
	return os.TempDir()
}
