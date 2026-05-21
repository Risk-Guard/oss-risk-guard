package npm

import (
	"os"
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"testing"
)

func TestParseManifest_PrivateTrue(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"name": "my-private-app",
		"private": true,
		"dependencies": {
			"express": "^4.18.0"
		}
	}`
	err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0o600)
	if err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	detected := models.DetectedManifest{
		Ecosystem: "npm",
		Paths:     []string{"package.json"},
	}

	result, err := ParseManifest(detected, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Private {
		t.Error("expected result.Private to be true")
	}
}

func TestParseManifest_PrivateFalse(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"name": "my-public-lib",
		"dependencies": {
			"lodash": "^4.17.0"
		}
	}`
	err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0o600)
	if err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	detected := models.DetectedManifest{
		Ecosystem: "npm",
		Paths:     []string{"package.json"},
	}

	result, err := ParseManifest(detected, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Private {
		t.Error("expected result.Private to be false when not specified")
	}
}
