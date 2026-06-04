package environment

import (
	"context"
	"time"
)

// SharedConfig is the minimal config contract used by code shared between the
// local CLI and the server. Each binary supplies its own implementation.
type SharedConfig interface {
	GetSecureGit() bool
	GetCacheMaxAge() time.Duration
	GetCloneTimeout() time.Duration
}

type sharedConfigKey struct{}

func SetSharedConfig(ctx context.Context, c SharedConfig) context.Context {
	return context.WithValue(ctx, sharedConfigKey{}, c)
}

// GetSharedConfig retrieves the shared config from the context. Panics if
// missing to enforce initialization in the root command.
func GetSharedConfig(ctx context.Context) SharedConfig {
	c, ok := ctx.Value(sharedConfigKey{}).(SharedConfig)
	if !ok || c == nil {
		panic("shared config not found in context - ensure config is initialized in root command")
	}
	return c
}
