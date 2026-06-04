package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/riskguardignore"
)

func TestManifestIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".riskguardignore"), []byte("third_party/\nvendor/\n"), 0o600); err != nil {
		t.Fatalf("writing .riskguardignore: %v", err)
	}
	matcher, err := riskguardignore.NewMatcher(dir)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	cases := []struct {
		name string
		m    models.DetectedManifest
		want bool
	}{
		{"top-level kept", models.DetectedManifest{Paths: []string{"requirements.txt"}}, false},
		{"under ignored dir dropped", models.DetectedManifest{Paths: []string{"third_party/foo/setup.py"}}, true},
		{"grouped all-ignored dropped", models.DetectedManifest{Paths: []string{"vendor/x/pyproject.toml", "vendor/x/setup.py"}}, true},
		{"grouped mixed kept", models.DetectedManifest{Paths: []string{"vendor/x/pyproject.toml", "pkg/setup.py"}}, false},
		{"no paths kept", models.DetectedManifest{Paths: nil}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := manifestIgnored(matcher, c.m); got != c.want {
				t.Errorf("manifestIgnored = %v, want %v", got, c.want)
			}
		})
	}
}
