package main

import (
	"context"
	"fmt"
	"os"
	"risk-guard/src/overrides"

	"sigs.k8s.io/yaml"
)

type OverridesFile struct {
	Overrides []overrides.Override `json:"overrides"`
}

func loadOverridesFile(path string) (*overrides.Store, error) {
	if path == "" {
		return nil, nil
	}

	// #nosec G304 -- path is from CLI flag, user-controlled input is expected
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading overrides file: %w", err)
	}

	var file OverridesFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing overrides file: %w", err)
	}

	return overrides.NewStore(file.Overrides), nil
}

func loadAndSetupOverrides(ctx context.Context, filepath string) (context.Context, string, error) {
	if filepath == "" {
		return ctx, "", nil
	}

	store, err := loadOverridesFile(filepath)
	if err != nil {
		return ctx, "", err
	}

	ctx = overrides.SetStore(ctx, store)

	hash, err := overrides.Hash(store.GetAll())
	if err != nil {
		return ctx, "", err
	}

	return ctx, hash, nil
}
