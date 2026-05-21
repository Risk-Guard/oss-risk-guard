package gemfile

import (
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
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

type expectedDep struct {
	AnalysisIdentifier string
	Specifiers         []string
}

func TestExtractDependenciesFromGemfile_Static(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		expectedDeps []expectedDep
	}{
		{
			name:    "simple gem",
			content: `gem 'rack'`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{}},
			},
		},
		{
			name:    "gem with version",
			content: `gem 'rack', '>= 3.0.0'`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{">= 3.0.0"}},
			},
		},
		{
			name:    "gem with multiple versions",
			content: `gem 'rack', '>= 3.0.0', '< 4'`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{">= 3.0.0", "< 4"}},
			},
		},
		{
			name: "multiple gems",
			content: `gem 'rack'
gem 'tilt', '~> 2.0'
gem 'mustermann', '~> 3.0'`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{}},
				{AnalysisIdentifier: "package/rubygems/tilt", Specifiers: []string{"~> 2.0"}},
				{AnalysisIdentifier: "package/rubygems/mustermann", Specifiers: []string{"~> 3.0"}},
			},
		},
		{
			name:    "double quotes",
			content: `gem "rack", ">= 3.0.0"`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{">= 3.0.0"}},
			},
		},
		{
			name: "with source",
			content: `source 'https://rubygems.org'
gem 'rack'`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{}},
			},
		},
		{
			name: "with comments",
			content: `# This is a comment
gem 'rack' # inline comment
gem 'tilt'`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{}},
				{AnalysisIdentifier: "package/rubygems/tilt", Specifiers: []string{}},
			},
		},
		{
			name: "group blocks",
			content: `gem 'rack'

group :development do
  gem 'minitest'
  gem 'rubocop'
end

gem 'tilt'`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{}},
				{AnalysisIdentifier: "package/rubygems/minitest", Specifiers: []string{}},
				{AnalysisIdentifier: "package/rubygems/rubocop", Specifiers: []string{}},
				{AnalysisIdentifier: "package/rubygems/tilt", Specifiers: []string{}},
			},
		},
		{
			name: "platform check with regex",
			content: `gem 'nokogiri' unless RUBY_PLATFORM =~ /linux/i
gem 'rack'`,
			expectedDeps: []expectedDep{
				{AnalysisIdentifier: "package/rubygems/nokogiri", Specifiers: []string{}},
				{AnalysisIdentifier: "package/rubygems/rack", Specifiers: []string{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _, err := ExtractDependencies(tt.content, "Gemfile")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(deps) != len(tt.expectedDeps) {
				t.Fatalf("Expected %d dependencies, got %d", len(tt.expectedDeps), len(deps))
			}

			for i, expected := range tt.expectedDeps {
				actual := deps[i]
				if actual.AnalysisIdentifier != expected.AnalysisIdentifier {
					t.Errorf("Dependency %d: expected name %q, got %q", i, expected.AnalysisIdentifier, actual.AnalysisIdentifier)
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
		})
	}
}

func TestExtractDependenciesFromGemfile_WithConstants(t *testing.T) {
	content := `RACK_GEM = 'rack'
TILT_GEM = 'tilt'

gem RACK_GEM
gem TILT_GEM, '~> 2.0'`

	deps, _, err := ExtractDependencies(content, "Gemfile")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("Expected 2 dependencies, got %d", len(deps))
	}

	if deps[0].AnalysisIdentifier != "package/rubygems/rack" {
		t.Errorf("Expected first dep %q, got %q", "package/rubygems/rack", deps[0].AnalysisIdentifier)
	}

	if deps[1].AnalysisIdentifier != "package/rubygems/tilt" {
		t.Errorf("Expected second dep %q, got %q", "package/rubygems/tilt", deps[1].AnalysisIdentifier)
	}
}

func TestExtractDependenciesFromGemfile_Dynamic(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		expectedReason string
	}{
		{
			name:           "string interpolation",
			content:        `gem "rack-#{version}"`,
			expectedReason: "string interpolation",
		},
		{
			name:           "method call",
			content:        `gem get_name()`,
			expectedReason: "method call",
		},
		{
			name:           "module constant",
			content:        `gem MyGem::NAME`,
			expectedReason: "module constant",
		},
		{
			name:           "undefined variable",
			content:        `gem dep_name`,
			expectedReason: "variable reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, dynDeps, err := ExtractDependencies(tt.content, "Gemfile")
			assertDynamicDependencyResult(t, err, dynDeps, len(deps), tt.expectedReason)
		})
	}
}

func TestExtractDependenciesFromGemfile_RealWorld(t *testing.T) {
	content := `# frozen_string_literal: true

source 'https://rubygems.org'
gemspec

gem 'rake'

rack_version = ENV['rack'].to_s
rack_version = nil if rack_version.empty? || (rack_version == 'stable')
rack_version = { github: 'rack/rack' } if rack_version == 'head'
gem 'rack', rack_version

gem 'rackup'
gem 'puma'
gem 'zeitwerk'

gem 'minitest', '~> 5.0'
gem 'rack-test'
gem 'rubocop', '~> 1.32.0', require: false
gem 'yard'

gem 'asciidoctor'
gem 'builder'
gem 'haml', '~> 6'
gem 'kramdown'`

	deps, dynDeps, err := ExtractDependencies(content, "Gemfile")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedStatic := []string{
		"rake", "rack", "rackup", "puma", "zeitwerk", "minitest",
		"rack-test", "rubocop", "yard", "asciidoctor", "builder",
		"haml", "kramdown",
	}

	if len(deps) != len(expectedStatic) {
		t.Logf("Got %d dependencies:", len(deps))
		for i, dep := range deps {
			t.Logf("  %d: %s (specifiers: %v)", i, dep.AnalysisIdentifier, dep.Specifiers)
		}
		t.Fatalf("Expected %d dependencies, got %d", len(expectedStatic), len(deps))
	}

	for i, expName := range expectedStatic {
		expectedID := "package/rubygems/" + expName
		if deps[i].AnalysisIdentifier != expectedID {
			t.Errorf("Dependency %d: expected %q, got %q", i, expectedID, deps[i].AnalysisIdentifier)
		}
	}

	if len(dynDeps) != 0 {
		t.Errorf("Expected 0 dynamic dependencies (rack_version is just a version specifier, not the gem name), got %d", len(dynDeps))
	}

	rackIdx := 1
	if len(deps[rackIdx].Specifiers) != 0 {
		t.Errorf("Expected rack to have 0 specifiers (rack_version variable is not parsed), got %d", len(deps[rackIdx].Specifiers))
	}
}
