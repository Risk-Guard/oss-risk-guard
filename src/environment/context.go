package environment

import (
	"context"
)

type configKey struct{}

// SetConfig stores the environment configuration in the context.
func SetConfig(ctx context.Context, cfg *Config) context.Context {
	return context.WithValue(ctx, configKey{}, cfg)
}
