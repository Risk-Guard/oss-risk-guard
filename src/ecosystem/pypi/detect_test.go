package pypi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectManifests_SetupPyWithLockfile(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte("setup(name='foo')"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "uv.lock"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	var setupManifest *struct {
		lockfile       *string
		packageManager *string
	}
	for _, m := range manifests {
		for _, p := range m.Paths {
			if filepath.Base(p) == "setup.py" {
				setupManifest = &struct {
					lockfile       *string
					packageManager *string
				}{m.Lockfile, m.PackageManager}
				break
			}
		}
	}

	if setupManifest == nil {
		t.Fatal("setup.py manifest not detected")
	}
	if setupManifest.lockfile == nil {
		t.Error("expected Lockfile to be set for setup.py when uv.lock exists")
	}
	if setupManifest.packageManager == nil {
		t.Error("expected PackageManager to be set for setup.py when uv.lock exists")
	} else if *setupManifest.packageManager != "uv" {
		t.Errorf("expected PackageManager 'uv', got %q", *setupManifest.packageManager)
	}
}

func TestDetectManifests_SetupCfgWithLockfile(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "setup.cfg"), []byte("[metadata]\nname = foo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "uv.lock"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, m := range manifests {
		for _, p := range m.Paths {
			if filepath.Base(p) == "setup.cfg" {
				found = true
				if m.Lockfile == nil {
					t.Error("expected Lockfile to be set for setup.cfg when uv.lock exists")
				}
				if m.PackageManager == nil {
					t.Error("expected PackageManager to be set for setup.cfg when uv.lock exists")
				}
			}
		}
	}
	if !found {
		t.Fatal("setup.cfg manifest not detected")
	}
}

func TestDetectManifests_PyprojectAndSetupPy_GroupedIntoOneManifest(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte("[project]\nname = \"foo\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte("from setuptools import setup\nsetup()\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest grouping pyproject.toml + setup.py, got %d", len(manifests))
	}
	paths := manifests[0].Paths
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(paths), paths)
	}

	hasPyproject, hasSetupPy := false, false
	for _, p := range paths {
		switch filepath.Base(p) {
		case "pyproject.toml":
			hasPyproject = true
		case "setup.py":
			hasSetupPy = true
		}
	}
	if !hasPyproject || !hasSetupPy {
		t.Errorf("expected paths to contain pyproject.toml and setup.py, got %v", paths)
	}
}

func TestDetectManifests_PyprojectAndSetupCfgAndSetupPy_GroupedIntoOneManifest(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte("[project]\nname = \"foo\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "setup.cfg"), []byte("[metadata]\nname = foo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte("from setuptools import setup\nsetup()\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest grouping all three files, got %d", len(manifests))
	}
	if len(manifests[0].Paths) != 3 {
		t.Fatalf("expected 3 paths, got %d: %v", len(manifests[0].Paths), manifests[0].Paths)
	}
}

func TestDetectManifests_PyprojectAlone_StillDetected(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte("[project]\nname = \"foo\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest for pyproject.toml alone, got %d", len(manifests))
	}
	if len(manifests[0].Paths) != 1 || filepath.Base(manifests[0].Paths[0]) != "pyproject.toml" {
		t.Errorf("expected single path pyproject.toml, got %v", manifests[0].Paths)
	}
}

func TestDetectManifests_PyprojectAndRequirements_StaySeparate(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte("[project]\nname = \"foo\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte("requests>=2.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(manifests) != 2 {
		t.Fatalf("expected 2 separate manifests for pyproject.toml + requirements.txt, got %d", len(manifests))
	}
}

func TestDetectManifests_SetupPyWithoutLockfile(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte("setup(name='foo')"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range manifests {
		for _, p := range m.Paths {
			if filepath.Base(p) == "setup.py" {
				if m.Lockfile != nil {
					t.Error("expected Lockfile to be nil when no lockfile exists")
				}
				return
			}
		}
	}
	t.Fatal("setup.py manifest not detected")
}
