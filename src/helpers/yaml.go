package helpers

import (
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"
)

func WriteYAML(path string, data any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	out, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling YAML: %w", err)
	}

	// #nosec G306 -- file permissions are intentionally 0600
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("writing file %s: %w", path, err)
	}

	return nil
}
