package environment

import (
	"context"
)

type configKey struct{}

// SetConfig stores the environment configuration in the context.
func SetConfig(ctx context.Context, cfg *Config) context.Context {
	return context.WithValue(ctx, configKey{}, cfg)
}

// GetConfig retrieves the environment configuration from the context.
// Panics if no config is found - this enforces proper initialization in the root command.
func GetConfig(ctx context.Context) *Config {
	cfg, ok := ctx.Value(configKey{}).(*Config)
	if !ok || cfg == nil {
		panic("environment config not found in context - ensure config is initialized in root command")
	}
	return cfg
}
