package pypi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// uv.lock edges must carry the manifest Location (file + line of the dep in
// pyproject.toml) so SARIF physicalLocation gets populated.
//   - Direct edges (ParentKey == "") inherit the manifest dep's Location.
//   - Transitive edges inherit the Location of the direct ancestor.
func TestParseManifest_UvLockfile_CarriesManifestLocation(t *testing.T) {
	dir := t.TempDir()
	pyproject := `[project]
name = "demo"
version = "0.1.0"
dependencies = [
  "requests>=2.31.0",
  "pytest>=7.0",
]
`
	// requests depends on certifi (transitive)
	uvLock := `version = 1
requires-python = ">=3.10"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
  { name = "requests" },
  { name = "pytest" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "certifi" },
]

[[package]]
name = "certifi"
version = "2024.1.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "7.4.4"
source = { registry = "https://pypi.org/simple" }
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(pyproject), 0o600); err != nil {
		t.Fatalf("write pyproject.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(uvLock), 0o600); err != nil {
		t.Fatalf("write uv.lock: %v", err)
	}

	lockfile := "uv.lock"
	detected := models.DetectedManifest{
		Ecosystem: "pypi",
		Paths:     []string{"pyproject.toml"},
		Lockfile:  &lockfile,
	}

	result, err := ParseManifest(detected, dir)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(result.LockfileDependencies) == 0 {
		t.Fatalf("expected lockfile edges, got none")
	}

	// pyproject lines (1-indexed):
	//   line 5: "requests>=2.31.0"
	//   line 6: "pytest>=7.0"
	want := map[string]int{
		"package/pypi/requests?version=2.31.0":  5,
		"package/pypi/pytest?version=7.4.4":     6,
		"package/pypi/certifi?version=2024.1.4": 5, // inherited from requests
	}

	byChild := map[string]models.DepsTreeEdge{}
	for _, e := range result.LockfileDependencies {
		byChild[e.ChildKey] = e
	}
	for key, wantLine := range want {
		e, ok := byChild[key]
		if !ok {
			t.Errorf("missing edge for %s", key)
			continue
		}
		if e.Location == nil || e.Location.File == nil {
			t.Errorf("%s: expected Location with File set, got %+v", key, e.Location)
			continue
		}
		if *e.Location.File != "pyproject.toml" {
			t.Errorf("%s: File = %q, want pyproject.toml", key, *e.Location.File)
		}
		got := -1
		if e.Location.LineNumber != nil {
			got = *e.Location.LineNumber
		}
		if got != wantLine {
			t.Errorf("%s: LineNumber = %d, want %d", key, got, wantLine)
		}
	}
}

func TestParseManifest_SetupPyNoSetupCall_NotAnError(t *testing.T) {
	tmpDir := t.TempDir()

	content := `# no setup() call here
x = 1 + 2
print("hello")
`
	if err := os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := models.DetectedManifest{
		Ecosystem: "pypi",
		Paths:     []string{"setup.py"},
	}

	result, err := ParseManifest(manifest, tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if result.ParseError != nil {
		t.Errorf("setup.py without setup() call is valid Python, not a parse error, got %q", *result.ParseError)
	}
}

func TestParseManifest_SetupPyNoNameArg_NotAnError(t *testing.T) {
	tmpDir := t.TempDir()

	content := "from setuptools import setup\nsetup(ext_modules=[])\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := models.DetectedManifest{
		Ecosystem: "pypi",
		Paths:     []string{"setup.py"},
	}

	result, err := ParseManifest(manifest, tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if result.ParseError != nil {
		t.Errorf("setup.py with setup() but no name= is valid, not a parse error, got %q", *result.ParseError)
	}
}

func TestParseManifest_SetupPyErrorSuppressedWhenSetupCfgProvidesName(t *testing.T) {
	tmpDir := t.TempDir()

	setupCfg := "[metadata]\nname = my-package\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "setup.cfg"), []byte(setupCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	setupPy := "from setuptools import setup\nsetup()\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte(setupPy), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := models.DetectedManifest{
		Ecosystem: "pypi",
		Paths:     []string{"setup.cfg", "setup.py"},
	}

	result, err := ParseManifest(manifest, tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if result.ParseError != nil {
		t.Errorf("expected no ParseError when setup.cfg provides the name, got %q", *result.ParseError)
	}
	if result.Name == nil || *result.Name != "my-package" {
		t.Errorf("expected name 'my-package' from setup.cfg, got %v", result.Name)
	}
}

func TestParseManifest_SetupPyErrorSuppressedWhenPyprojectProvidesName(t *testing.T) {
	tmpDir := t.TempDir()

	pyprojectToml := "[project]\nname = \"my-package\"\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte(pyprojectToml), 0o600); err != nil {
		t.Fatal(err)
	}

	setupPy := "from setuptools import setup\nsetup(ext_modules=[])\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte(setupPy), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := models.DetectedManifest{
		Ecosystem: "pypi",
		Paths:     []string{"pyproject.toml", "setup.py"},
	}

	result, err := ParseManifest(manifest, tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if result.ParseError != nil {
		t.Errorf("expected no ParseError when pyproject.toml provides the name, got %q", *result.ParseError)
	}
	if result.Name == nil || *result.Name != "my-package" {
		t.Errorf("expected name 'my-package' from pyproject.toml, got %v", result.Name)
	}
}

func TestParseManifest_SetupPyValid(t *testing.T) {
	tmpDir := t.TempDir()

	content := `from setuptools import setup
setup(name='my-package')
`
	if err := os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := models.DetectedManifest{
		Ecosystem: "pypi",
		Paths:     []string{"setup.py"},
	}

	result, err := ParseManifest(manifest, tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if result.ParseError != nil {
		t.Errorf("expected no ParseError for valid setup.py, got %q", *result.ParseError)
	}
	if result.Name == nil || *result.Name != "my-package" {
		t.Errorf("expected name 'my-package', got %v", result.Name)
	}
}
