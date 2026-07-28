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

func TestParseBuildSystemRequiresDev(t *testing.T) {
	content := `
[build-system]
requires = ["setuptools>=77", "cmake>=3.27", "numpy"]
build-backend = "setuptools.build_meta"
`
	deps, err := Parse(content, "pyproject.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dev := make(map[string]bool)
	for _, d := range deps {
		dev[d.AnalysisIdentifier] = d.Dev
	}
	for _, want := range []string{"package/pypi/setuptools", "package/pypi/cmake", "package/pypi/numpy"} {
		got, ok := dev[want]
		if !ok {
			t.Errorf("expected build dep %s to be parsed", want)
			continue
		}
		if !got {
			t.Errorf("expected build dep %s to be Dev=true", want)
		}
	}
}

func TestParseOptionalDependenciesRuntime(t *testing.T) {
	content := `
[project]
name = "demo"

[project.optional-dependencies]
optree = ["optree>=0.13.0"]
opt-einsum = ["opt-einsum>=3.3"]
`
	deps, err := Parse(content, "pyproject.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dev := make(map[string]bool)
	for _, d := range deps {
		dev[d.AnalysisIdentifier] = d.Dev
	}
	for _, want := range []string{"package/pypi/optree", "package/pypi/opt-einsum"} {
		got, ok := dev[want]
		if !ok {
			t.Errorf("expected optional dep %s to be parsed", want)
			continue
		}
		if got {
			t.Errorf("expected optional dep %s to be Dev=false (production-reachable)", want)
		}
	}
}

func TestParseDependencyGroupsDevAndSkipsInclude(t *testing.T) {
	content := `
[dependency-groups]
test = ["pytest>=7", "hypothesis"]
dev = [{include-group = "test"}, "black"]
`
	deps, err := Parse(content, "pyproject.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dev := make(map[string]bool)
	for _, d := range deps {
		dev[d.AnalysisIdentifier] = d.Dev
	}
	for _, want := range []string{"package/pypi/pytest", "package/pypi/hypothesis", "package/pypi/black"} {
		got, ok := dev[want]
		if !ok {
			t.Errorf("expected group dep %s to be parsed", want)
			continue
		}
		if !got {
			t.Errorf("expected group dep %s to be Dev=true", want)
		}
	}
	// The {include-group = "test"} table references another group and is not a
	// package, so it must not produce a spurious dependency.
	if len(deps) != 3 {
		t.Errorf("expected 3 deps (include-group skipped), got %d: %v", len(deps), dev)
	}
}

// TestParseDynamicRuntimeDepsStillGetsBuildAndGroups mirrors pytorch: runtime
// dependencies are declared dynamic (so [project.dependencies] is empty), but
// build-system, optional, and dependency-group deps must still be enumerated.
func TestParseDynamicRuntimeDepsStillGetsBuildAndGroups(t *testing.T) {
	content := `
[build-system]
requires = ["setuptools", "numpy"]

[project]
name = "torch"
dynamic = ["dependencies", "version"]

[project.optional-dependencies]
optree = ["optree>=0.13.0"]

[dependency-groups]
dev = ["expecttest>=0.3.0", "filelock"]
`
	deps, err := Parse(content, "pyproject.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := make(map[string]bool)
	for _, d := range deps {
		got[d.AnalysisIdentifier] = true
	}
	for _, want := range []string{
		"package/pypi/setuptools", "package/pypi/numpy",
		"package/pypi/optree", "package/pypi/expecttest", "package/pypi/filelock",
	} {
		if !got[want] {
			t.Errorf("expected %s to be parsed, got %v", want, got)
		}
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

func TestParsePrivateDoNotUploadClassifier(t *testing.T) {
	content := `
[project]
name = "benchmark_cpp_extension"
classifiers = [
    "Programming Language :: Python :: 3",
    "Private :: Do Not Upload",
]
`
	if !ParsePrivate(content) {
		t.Error("expected ParsePrivate=true for 'Private :: Do Not Upload' classifier")
	}
}

func TestParsePrivateAnyPrivateCategory(t *testing.T) {
	content := `
[project]
name = "internal-tool"
classifiers = ["Private :: Internal"]
`
	if !ParsePrivate(content) {
		t.Error("expected ParsePrivate=true for any 'Private ::' classifier")
	}
}

func TestParsePrivateCaseAndSpacingInsensitive(t *testing.T) {
	content := `
[project]
name = "internal-tool"
classifiers = ["private::Do Not Upload"]
`
	if !ParsePrivate(content) {
		t.Error("expected ParsePrivate=true regardless of case and spacing")
	}
}

func TestParsePrivateFalseForPublicPackage(t *testing.T) {
	content := `
[project]
name = "requests"
classifiers = [
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: Apache Software License",
]
`
	if ParsePrivate(content) {
		t.Error("expected ParsePrivate=false when no 'Private ::' classifier is present")
	}
}

func TestParsePrivateFalseWhenNoClassifiers(t *testing.T) {
	content := `
[project]
name = "requests"
`
	if ParsePrivate(content) {
		t.Error("expected ParsePrivate=false when classifiers are absent")
	}
}
