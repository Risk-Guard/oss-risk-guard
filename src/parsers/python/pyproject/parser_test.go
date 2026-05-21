package pyproject

import (
	"testing"
)

func TestParsePoetryDependenciesNotDev(t *testing.T) {
	content := `
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28"
flask = "^2.0"
`
	deps, err := Parse(content, "pyproject.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, dep := range deps {
		if dep.Dev {
			t.Errorf("expected Dev=false for poetry dependency %s", dep.AnalysisIdentifier)
		}
	}

	if len(deps) != 2 {
		t.Errorf("expected 2 deps (python skipped), got %d", len(deps))
	}
}

func TestParsePoetryDevDependenciesDev(t *testing.T) {
	content := `
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28"

[tool.poetry.dev-dependencies]
pytest = "^7.0"
black = "^23.0"
`
	deps, err := Parse(content, "pyproject.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	devByName := make(map[string]bool)
	for _, dep := range deps {
		devByName[dep.AnalysisIdentifier] = dep.Dev
	}

	if devByName["package/pypi/requests"] {
		t.Error("requests should not be dev")
	}
	if !devByName["package/pypi/pytest"] {
		t.Error("pytest should be dev")
	}
	if !devByName["package/pypi/black"] {
		t.Error("black should be dev")
	}
}

func TestParseNameFlitMetadataModule(t *testing.T) {
	content := `
[build-system]
requires = ["flit_core >=2,<4"]
build-backend = "flit_core.buildapi"

[tool.flit.metadata]
module = "ptyprocess"
author = "Thomas Kluyver"
`
	result := ParseName(content)
	if result.Name == nil {
		t.Fatal("expected name to be parsed from flit metadata")
	}
	if *result.Name != "ptyprocess" {
		t.Errorf("expected name 'ptyprocess', got '%s'", *result.Name)
	}
}

func TestParseNameFlitMetadataDistName(t *testing.T) {
	content := `
[tool.flit.metadata]
module = "ptyprocess"
dist-name = "py-ptyprocess"
`
	result := ParseName(content)
	if result.Name == nil {
		t.Fatal("expected name to be parsed from flit metadata dist-name")
	}
	if *result.Name != "py-ptyprocess" {
		t.Errorf("expected name 'py-ptyprocess', got '%s'", *result.Name)
	}
}

func TestParseNameProjectOverridesFlit(t *testing.T) {
	content := `
[project]
name = "from-project"

[tool.flit.metadata]
module = "from-flit"
`
	result := ParseName(content)
	if result.Name == nil {
		t.Fatal("expected name to be parsed")
	}
	if *result.Name != "from-project" {
		t.Errorf("expected [project].name to win, got '%s'", *result.Name)
	}
}

func TestParseProjectDependenciesNotDev(t *testing.T) {
	content := `
[project]
name = "my-project"
dependencies = [
    "requests>=2.28",
    "flask>=2.0",
]
`
	deps, err := Parse(content, "pyproject.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	for _, dep := range deps {
		if dep.Dev {
			t.Errorf("expected Dev=false for project dependency %s", dep.AnalysisIdentifier)
		}
	}
}
