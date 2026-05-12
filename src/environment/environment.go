package environment

import (
	"errors"
	"fmt"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config holds the minimal environment configuration consumed by oss-risk-guard's
// library code. Downstream consumers (e.g. the risk-guard CLI) embed this struct
// to add their own fields.
type Config struct {
	FetchState string
}

func (c *Config) GetNoFetch() bool {
	return c.FetchState == "no-fetch"
}

func (c *Config) GetWriteFetchOnly() bool {
	return c.FetchState == "write-fetch-only"
}

func (c *Config) SetFetchState(noFetch, writeFetchOnly bool) error {
	if noFetch && writeFetchOnly {
		return fmt.Errorf("--no-fetch and --write-fetch-only are mutually exclusive")
	}
	if noFetch {
		c.FetchState = "no-fetch"
		return nil
	}
	if writeFetchOnly {
		c.FetchState = "write-fetch-only"
		return nil
	}
	c.FetchState = "normal"
	return nil
}

// Load returns the base environment configuration. It loads a .env file from
// the current directory if present.
func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load .env file: %w", err)
	}

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse environment variables: %w", err)
	}
	return cfg, nil
}
