package pypi

import (
	"os"
	"path/filepath"
	"risk-guard/src/models"
	"testing"
)

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
