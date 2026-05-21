package registry

import (
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	retrieved, err := Get("npm")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if retrieved.Ecosystem != "npm" {
		t.Errorf("Expected ecosystem 'npm', got %q", retrieved.Ecosystem)
	}

	if retrieved.Source.URL != "https://registry.npmjs.org" {
		t.Errorf("Expected registry URL 'https://registry.npmjs.org', got %q", retrieved.Source.URL)
	}
}

func TestGetNotFound(t *testing.T) {
	_, err := Get("nonexistent")
	if err == nil {
		t.Errorf("Get() should return error for nonexistent ecosystem")
	}

	if !strings.Contains(err.Error(), "unsupported ecosystem") {
		t.Errorf("Expected error message about 'unsupported ecosystem', got: %s", err.Error())
	}
}

func TestMustGet(t *testing.T) {
	// Should not panic for existing ecosystem
	retrieved := MustGet("npm")
	if retrieved.Ecosystem != "npm" {
		t.Errorf("Expected ecosystem 'npm', got %q", retrieved.Ecosystem)
	}
}

func TestMustGetPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("MustGet() should panic for nonexistent ecosystem")
		}
	}()

	MustGet("nonexistent")
}

func TestEcosystems(t *testing.T) {
	ecosystems := Ecosystems()

	if len(ecosystems) != 3 {
		t.Fatalf("Expected 3 ecosystems, got %d", len(ecosystems))
	}

	expected := []string{"npm", "pypi", "rubygems"}
	for i, eco := range expected {
		if ecosystems[i] != eco {
			t.Errorf("Expected ecosystems[%d] = %q, got %q", i, eco, ecosystems[i])
		}
	}
}

func TestBuildPackageURL(t *testing.T) {
	meta, err := Get("npm")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	url := meta.BuildPackageURL("express")
	expected := "https://registry.npmjs.org/express"

	if url != expected {
		t.Errorf("Expected URL %q, got %q", expected, url)
	}
}

func TestBuildPackageURLWithJSON(t *testing.T) {
	meta, err := Get("pypi")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	url := meta.BuildPackageURL("requests")
	expected := "https://pypi.org/pypi/requests/json"

	if url != expected {
		t.Errorf("Expected URL %q, got %q", expected, url)
	}
}

func TestGetPyPI(t *testing.T) {
	meta, err := Get("pypi")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if meta.Ecosystem != "pypi" {
		t.Errorf("Expected ecosystem 'pypi', got %q", meta.Ecosystem)
	}

	if meta.OSVEcosystem != "PyPI" {
		t.Errorf("Expected OSVEcosystem 'PyPI', got %q", meta.OSVEcosystem)
	}

	if meta.GHSAEcosystem != "pip" {
		t.Errorf("Expected GHSAEcosystem 'pip', got %q", meta.GHSAEcosystem)
	}
}

func TestGetNPM(t *testing.T) {
	meta, err := Get("npm")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if meta.Ecosystem != "npm" {
		t.Errorf("Expected ecosystem 'npm', got %q", meta.Ecosystem)
	}

	if meta.OSVEcosystem != "npm" {
		t.Errorf("Expected OSVEcosystem 'npm', got %q", meta.OSVEcosystem)
	}

	if meta.GHSAEcosystem != "npm" {
		t.Errorf("Expected GHSAEcosystem 'npm', got %q", meta.GHSAEcosystem)
	}
}
