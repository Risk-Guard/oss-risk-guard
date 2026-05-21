package rubygems

import (
	"os"
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"strings"
	"testing"
)

func TestParseManifest_UnsupportedFilename(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rubygems-parse-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	if err := os.WriteFile(filepath.Join(tmpDir, "random.txt"), []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := models.DetectedManifest{
		Ecosystem: "rubygems",
		Paths:     []string{"random.txt"},
	}

	_, err = ParseManifest(manifest, tmpDir)
	if err == nil {
		t.Error("Expected error for unsupported filename, got nil")
	}
}

func TestParseManifest_GemfileLineNumbers(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rubygems-parse-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	gemfileContent := `source 'https://rubygems.org'

gem 'rails', '~> 7.0'
gem 'pg', '>= 1.1'
gem 'puma', '~> 5.0'
`
	if err := os.WriteFile(filepath.Join(tmpDir, "Gemfile"), []byte(gemfileContent), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := models.DetectedManifest{
		Ecosystem: "rubygems",
		Paths:     []string{"Gemfile"},
	}

	result, err := ParseManifest(manifest, tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if result.ParseError != nil {
		t.Fatalf("Unexpected ParseError: %s", *result.ParseError)
	}

	if len(result.Dependencies) < 3 {
		t.Fatalf("Expected at least 3 dependencies, got %d", len(result.Dependencies))
	}

	lineNumbers := make(map[int]bool)
	for i, dep := range result.Dependencies {
		if dep.Location == nil || dep.Location.LineNumber == nil {
			t.Errorf("Dependency %d (%s) has nil Location or LineNumber", i, dep.AnalysisIdentifier)
			continue
		}
		ln := *dep.Location.LineNumber
		if lineNumbers[ln] {
			t.Errorf("Duplicate LineNumber %d found - loop pointer bug detected", ln)
		}
		lineNumbers[ln] = true
	}

	if len(lineNumbers) != len(result.Dependencies) {
		t.Errorf("Expected %d unique line numbers, got %d - loop pointer bug detected",
			len(result.Dependencies), len(lineNumbers))
	}
}

func TestParseManifest_GemspecLineNumbers(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rubygems-parse-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	gemspecContent := `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.version = "1.0.0"
  spec.add_dependency "nokogiri", "~> 1.0"
  spec.add_dependency "rails", ">= 6.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
`
	if err := os.WriteFile(filepath.Join(tmpDir, "example.gemspec"), []byte(gemspecContent), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := models.DetectedManifest{
		Ecosystem: "rubygems",
		Paths:     []string{"example.gemspec"},
	}

	result, err := ParseManifest(manifest, tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if result.ParseError != nil {
		t.Fatalf("Unexpected ParseError: %s", *result.ParseError)
	}

	if len(result.Dependencies) < 2 {
		t.Fatalf("Expected at least 2 dependencies, got %d", len(result.Dependencies))
	}

	lineNumbers := make(map[int]bool)
	for i, dep := range result.Dependencies {
		if dep.Location == nil || dep.Location.LineNumber == nil {
			t.Errorf("Dependency %d (%s) has nil Location or LineNumber", i, dep.AnalysisIdentifier)
			continue
		}
		ln := *dep.Location.LineNumber
		if lineNumbers[ln] {
			t.Errorf("Duplicate LineNumber %d found - loop pointer bug detected", ln)
		}
		lineNumbers[ln] = true
	}

	if len(lineNumbers) != len(result.Dependencies) {
		t.Errorf("Expected %d unique line numbers, got %d - loop pointer bug detected",
			len(result.Dependencies), len(lineNumbers))
	}
}

func TestParseManifest_GemspecNameParseError(t *testing.T) {
	tmpDir := t.TempDir()

	content := `class MyGem
  def name
    'my-gem'
  end
end
`
	if err := os.WriteFile(filepath.Join(tmpDir, "broken.gemspec"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := models.DetectedManifest{
		Ecosystem: "rubygems",
		Paths:     []string{"broken.gemspec"},
	}

	result, err := ParseManifest(manifest, tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if result.ParseError == nil {
		t.Fatal("expected ParseError when gemspec has no Gem::Specification.new")
	}
	if !strings.Contains(*result.ParseError, "failed to parse gemspec name") {
		t.Errorf("expected ParseError to mention 'failed to parse gemspec name', got %q", *result.ParseError)
	}
}
