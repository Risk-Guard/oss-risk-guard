package gemspec

import (
	"os"
	"path/filepath"
	"risk-guard/src/models"
	"strings"
	"testing"
)

func assertDynamicDependencyResult(
	t *testing.T,
	err error,
	dynDeps []models.DynamicDependency,
	staticDepCount int,
	expectedReason string,
) {
	t.Helper()

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(dynDeps) != 1 {
		t.Fatalf("Expected 1 dynamic dependency, got %d", len(dynDeps))
	}

	if !strings.Contains(dynDeps[0].Reason, expectedReason) {
		t.Errorf("Expected reason to contain %q, got %q",
			expectedReason, dynDeps[0].Reason)
	}

	if staticDepCount != 0 {
		t.Errorf("Expected no static dependencies, got %d", staticDepCount)
	}
}

func TestParseGemspec_ConstructorWithLiteral(t *testing.T) {
	tmpDir := t.TempDir()
	gemspecPath := filepath.Join(tmpDir, "test.gemspec")

	content := `Gem::Specification.new 'my-gem', '1.0.0' do |s|
  s.summary = 'Test gem'
end`

	if err := os.WriteFile(gemspecPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	result := Parse(gemspecPath)

	if result.Error != nil {
		t.Fatalf("Unexpected error: %v", result.Error)
	}

	if result.Name != "my-gem" {
		t.Errorf("Expected name %q, got %q", "my-gem", result.Name)
	}

	if result.IsDynamic {
		t.Errorf("Expected static name, got dynamic")
	}
}

func TestParseGemspec_AssignmentWithLiteral(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name: "single quotes",
			content: `Gem::Specification.new do |s|
  s.name = 'my-gem'
end`,
			expected: "my-gem",
		},
		{
			name: "double quotes without interpolation",
			content: `Gem::Specification.new do |s|
  s.name = "my-gem"
end`,
			expected: "my-gem",
		},
		{
			name: "explicit-gem-string",
			content: `Gem::Specification.new do |s|
  s.name = 'explicit-gem-string'
end`,
			expected: "explicit-gem-string",
		},
		{
			name: "spec parameter",
			content: `Gem::Specification.new do |spec|
  spec.name = 'my-gem'
end`,
			expected: "my-gem",
		},
		{
			name: "gem parameter",
			content: `Gem::Specification.new do |gem|
  gem.name = 'my-gem'
end`,
			expected: "my-gem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gemspecPath := filepath.Join(tmpDir, "test.gemspec")

			if err := os.WriteFile(gemspecPath, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}

			result := Parse(gemspecPath)

			if result.Error != nil {
				t.Fatalf("Unexpected error: %v", result.Error)
			}

			if result.Name != tt.expected {
				t.Errorf("Expected name %q, got %q", tt.expected, result.Name)
			}

			if result.IsDynamic {
				t.Errorf("Expected static name, got dynamic")
			}
		})
	}
}

func TestParseGemspec_ConstantResolution(t *testing.T) {
	tmpDir := t.TempDir()
	gemspecPath := filepath.Join(tmpDir, "test.gemspec")

	content := `NAME = 'my-gem'

Gem::Specification.new do |s|
  s.name = NAME
end`

	if err := os.WriteFile(gemspecPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	result := Parse(gemspecPath)

	if result.Error != nil {
		t.Fatalf("Unexpected error: %v", result.Error)
	}

	if result.Name != "my-gem" {
		t.Errorf("Expected resolved name %q, got %q", "my-gem", result.Name)
	}

	if result.IsDynamic {
		t.Errorf("Expected static name after constant resolution, got dynamic")
	}
}

func TestParseGemspec_DynamicPatterns(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		expectedReason string
	}{
		{
			name: "string interpolation",
			content: `Gem::Specification.new do |s|
  s.name = "my-#{prefix}-gem"
end`,
			expectedReason: "name uses string interpolation",
		},
		{
			name: "method call",
			content: `Gem::Specification.new do |s|
  s.name = get_name()
end`,
			expectedReason: "name uses method call",
		},
		{
			name: "File module",
			content: `Gem::Specification.new do |s|
  s.name = File.read('VERSION')
end`,
			expectedReason: "name uses method call",
		},
		{
			name: "module constant",
			content: `Gem::Specification.new do |s|
  s.name = MyGem::NAME
end`,
			expectedReason: "name uses module constant",
		},
		{
			name: "array lookup",
			content: `Gem::Specification.new do |s|
  s.name = names[0]
end`,
			expectedReason: "name uses array/hash lookup",
		},
		{
			name: "hash lookup",
			content: `Gem::Specification.new do |s|
  s.name = config['name']
end`,
			expectedReason: "name uses array/hash lookup",
		},
		{
			name: "undefined variable",
			content: `Gem::Specification.new do |s|
  s.name = UNDEFINED_VAR
end`,
			expectedReason: "uses variable reference: UNDEFINED_VAR",
		},
		{
			name: "binary operator",
			content: `Gem::Specification.new do |s|
  s.name = 'my' + 'gem'
end`,
			expectedReason: "name uses binary operator: +",
		},
		{
			name: "explicit concat",
			content: `Gem::Specification.new do |s|
  s.name = 'explicit' + 'concat'
end`,
			expectedReason: "name uses binary operator: +",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gemspecPath := filepath.Join(tmpDir, "test.gemspec")

			if err := os.WriteFile(gemspecPath, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}

			result := Parse(gemspecPath)

			if result.Error != nil {
				t.Fatalf("Unexpected error: %v", result.Error)
			}

			if !result.IsDynamic {
				t.Errorf("Expected dynamic name, got static")
			}

			if result.DynamicReason != tt.expectedReason {
				t.Errorf("Expected reason %q, got %q", tt.expectedReason, result.DynamicReason)
			}
		})
	}
}

func TestParseGemspec_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		expectError   bool
		errorContains string
	}{
		{
			name:          "empty file",
			content:       "",
			expectError:   true,
			errorContains: "file is empty",
		},
		{
			name: "no Gem::Specification",
			content: `class MyGem
  def name
    'my-gem'
  end
end`,
			expectError:   true,
			errorContains: "no Gem::Specification.new found",
		},
		{
			name: "no name in spec",
			content: `Gem::Specification.new do |s|
  s.summary = 'Test gem'
end`,
			expectError:   true,
			errorContains: "no name found in Gem::Specification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gemspecPath := filepath.Join(tmpDir, "test.gemspec")

			if err := os.WriteFile(gemspecPath, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}

			result := Parse(gemspecPath)

			if tt.expectError {
				if result.Error == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errorContains)
				} else if !strings.Contains(result.Error.Error(), tt.errorContains) {
					t.Errorf("Expected error containing %q, got %q", tt.errorContains, result.Error.Error())
				}
			} else {
				if result.Error != nil {
					t.Errorf("Unexpected error: %v", result.Error)
				}
			}
		})
	}
}

func TestUnquoteString_Ruby(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single quotes",
			input:    "'my-gem'",
			expected: "my-gem",
		},
		{
			name:     "double quotes",
			input:    `"my-gem"`,
			expected: "my-gem",
		},
		{
			name:     "percent q literal",
			input:    "%q{my-gem}",
			expected: "my-gem",
		},
		{
			name:     "percent Q literal",
			input:    "%Q{my-gem}",
			expected: "my-gem",
		},
		{
			name:     "percent w bracket literal",
			input:    "%w[my-gem]",
			expected: "my-gem",
		},
		{
			name:     "percent q bracket literal",
			input:    "%q[my-gem]",
			expected: "my-gem",
		},
		{
			name:     "bare percent bracket literal",
			input:    "%[my-gem]",
			expected: "my-gem",
		},
		{
			name:     "empty string",
			input:    `""`,
			expected: "",
		},
		{
			name:     "empty single quotes",
			input:    "''",
			expected: "",
		},
		{
			name:     "with whitespace",
			input:    `  "my-gem"  `,
			expected: "my-gem",
		},
		{
			name:     "no quotes",
			input:    "my-gem",
			expected: "my-gem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UnquoteString(tt.input)
			if result != tt.expected {
				t.Errorf("UnquoteString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

type expectedDep struct {
	AnalysisIdentifier string
	Specifiers         []string
}

func TestExtractDependenciesFromGemspec_Static(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		expectedDeps    []expectedDep
		expectedDynamic int
	}{
		{
			name: "simple add_dependency",
			content: `Gem::Specification.new do |s|
  s.add_dependency 'rack'
end`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{}},
			},
		},
		{
			name: "add_dependency with version",
			content: `Gem::Specification.new do |s|
  s.add_dependency 'rack', '>= 3.0.0'
end`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{">= 3.0.0"}},
			},
		},
		{
			name: "add_dependency with multiple versions",
			content: `Gem::Specification.new do |s|
  s.add_dependency 'rack', '>= 3.0.0', '< 4'
end`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{">= 3.0.0", "< 4"}},
			},
		},
		{
			name: "add_runtime_dependency",
			content: `Gem::Specification.new do |s|
  s.add_runtime_dependency 'tilt', '~> 2.0'
end`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/tilt", Specifiers: []string{"~> 2.0"}},
			},
		},
		{
			name: "multiple dependencies",
			content: `Gem::Specification.new do |s|
  s.add_dependency 'rack', '>= 3.0.0'
  s.add_dependency 'tilt', '~> 2.0'
  s.add_dependency 'mustermann', '~> 3.0'
end`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{">= 3.0.0"}},
				{AnalysisIdentifier: "package/rubygems/tilt", Specifiers: []string{"~> 2.0"}},
				{AnalysisIdentifier: "package/rubygems/mustermann", Specifiers: []string{"~> 3.0"}},
			},
		},
		{
			name: "skip development dependencies",
			content: `Gem::Specification.new do |s|
  s.add_dependency 'rack'
  s.add_development_dependency 'minitest'
  s.add_dependency 'tilt'
end`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{}},
				{AnalysisIdentifier: "package/rubygems/tilt", Specifiers: []string{}},
			},
		},
		{
			name: "with parentheses",
			content: `Gem::Specification.new do |s|
  s.add_dependency('rack', '>= 3.0.0')
end`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{">= 3.0.0"}},
			},
		},
		{
			name: "double quotes",
			content: `Gem::Specification.new do |s|
  s.add_dependency "rack", ">= 3.0.0"
end`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{">= 3.0.0"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, dynDeps, err := ExtractDependencies(tt.content, "test.gemspec")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(deps) != len(tt.expectedDeps) {
				t.Fatalf("Expected %d dependencies, got %d", len(tt.expectedDeps), len(deps))
			}

			for i, expected := range tt.expectedDeps {
				actual := deps[i]
				if actual.AnalysisIdentifier != expected.AnalysisIdentifier {
					t.Errorf("Dependency %d: expected %q, got %q", i, expected.AnalysisIdentifier, actual.AnalysisIdentifier)
				}
				if len(actual.Specifiers) != len(expected.Specifiers) {
					t.Errorf("Dependency %d: expected %d specifiers, got %d", i, len(expected.Specifiers), len(actual.Specifiers))
				}
				for j, spec := range expected.Specifiers {
					if j >= len(actual.Specifiers) || actual.Specifiers[j] != spec {
						t.Errorf("Dependency %d: expected specifier %q, got %q", i, spec, actual.Specifiers[j])
					}
				}
			}

			if tt.expectedDynamic > 0 && len(dynDeps) != tt.expectedDynamic {
				t.Errorf("Expected %d dynamic dependencies, got %d", tt.expectedDynamic, len(dynDeps))
			}
		})
	}
}

func TestExtractDependenciesFromGemspec_WithConstants(t *testing.T) {
	content := `
VERSION = '4.2.1'
RACK_PROTECTION = 'rack-protection'

Gem::Specification.new do |s|
  s.add_dependency RACK_PROTECTION, VERSION
end`

	deps, _, err := ExtractDependencies(content, "test.gemspec")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(deps) != 1 {
		t.Fatalf("Expected 1 dependency, got %d", len(deps))
	}

	if deps[0].AnalysisIdentifier != "package/rubygems/rack-protection" {
		t.Errorf("Expected %q, got %q", "package/rubygems/rack-protection", deps[0].AnalysisIdentifier)
	}
}

func TestExtractDependenciesFromGemspec_Dynamic(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		expectedReason string
	}{
		{
			name: "string interpolation",
			content: `Gem::Specification.new do |s|
  s.add_dependency "rack-#{version}"
end`,
			expectedReason: "string interpolation",
		},
		{
			name: "method call",
			content: `Gem::Specification.new do |s|
  s.add_dependency get_name()
end`,
			expectedReason: "method call",
		},
		{
			name: "module constant",
			content: `Gem::Specification.new do |s|
  s.add_dependency MyGem::NAME
end`,
			expectedReason: "module constant",
		},
		{
			name: "undefined variable",
			content: `Gem::Specification.new do |s|
  s.add_dependency dep_name
end`,
			expectedReason: "variable reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, dynDeps, err := ExtractDependencies(tt.content, "test.gemspec")
			assertDynamicDependencyResult(t, err, dynDeps, len(deps), tt.expectedReason)
		})
	}
}

func TestExtractDependenciesFromGemspec_RealWorld(t *testing.T) {
	content := `# frozen_string_literal: true

version = File.read(File.expand_path('VERSION', __dir__)).strip

Gem::Specification.new 'sinatra', version do |s|
  s.description = 'Sinatra is a DSL for quickly creating web applications in Ruby with minimal effort.'

  s.add_dependency 'logger', '>= 1.6.0'
  s.add_dependency 'mustermann', '~> 3.0'
  s.add_dependency 'rack', '>= 3.0.0', '< 4'
  s.add_dependency 'rack-protection', version
  s.add_dependency 'rack-session', '>= 2.0.0', '< 3'
  s.add_dependency 'tilt', '~> 2.0'
end`

	deps, dynDeps, err := ExtractDependencies(content, "sinatra.gemspec")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expected := []string{"logger", "mustermann", "rack", "rack-protection", "rack-session", "tilt"}
	if len(deps) != len(expected) {
		t.Fatalf("Expected %d dependencies, got %d", len(expected), len(deps))
	}

	for i, expName := range expected {
		expectedID := "package/rubygems/" + expName
		if deps[i].AnalysisIdentifier != expectedID {
			t.Errorf("Dependency %d: expected %q, got %q", i, expectedID, deps[i].AnalysisIdentifier)
		}
	}

	if len(dynDeps) != 0 {
		t.Errorf("Expected 0 dynamic dependencies (version is just a specifier, not the name), got %d", len(dynDeps))
	}
}
