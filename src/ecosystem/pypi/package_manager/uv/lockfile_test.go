package uv

import (
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"testing"
)

func TestParseLockfileBasic(t *testing.T) {
	content := []byte(`
version = 1
requires-python = ">=3.9"

[[package]]
name = "certifi"
version = "2026.1.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "charset-normalizer"
version = "3.4.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "idna"
version = "3.11"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.32.5"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "certifi" },
    { name = "charset-normalizer" },
    { name = "idna" },
    { name = "urllib3" },
]

[[package]]
name = "test"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[[package]]
name = "urllib3"
version = "2.6.3"
source = { registry = "https://pypi.org/simple" }
`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	directDeps := make(map[string]bool)
	transitiveDeps := make(map[string]string)

	for _, edge := range edges {
		if edge.ParentKey == "" {
			directDeps[edge.ChildKey] = true
		} else {
			transitiveDeps[edge.ChildKey] = edge.ParentKey
		}
		if edge.Ecosystem != "pypi" {
			t.Errorf("expected ecosystem pypi, got %s", edge.Ecosystem)
		}
	}

	requestsKey := "package/pypi/requests?version=2.32.5"
	if !directDeps[requestsKey] {
		t.Errorf("requests should be a direct dep, got direct deps: %v", directDeps)
	}
	if len(directDeps) != 1 {
		t.Errorf("expected 1 direct dep, got %d: %v", len(directDeps), directDeps)
	}

	certifiKey := "package/pypi/certifi?version=2026.1.4"
	charsetKey := "package/pypi/charset-normalizer?version=3.4.4"
	idnaKey := "package/pypi/idna?version=3.11"
	urllib3Key := "package/pypi/urllib3?version=2.6.3"

	for _, key := range []string{certifiKey, charsetKey, idnaKey, urllib3Key} {
		if transitiveDeps[key] != requestsKey {
			t.Errorf("expected %s parent to be %s, got %s", key, requestsKey, transitiveDeps[key])
		}
	}
}

func TestParseLockfileEmpty(t *testing.T) {
	content := []byte(`
version = 1
requires-python = ">=3.9"

[[package]]
name = "my-project"
version = "0.1.0"
source = { virtual = "." }
`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(edges) != 0 {
		t.Errorf("expected 0 edges for project with no deps, got %d", len(edges))
	}
}

func TestParseLockfileNameNormalization(t *testing.T) {
	content := []byte(`
version = 1
requires-python = ">=3.9"

[[package]]
name = "My_Cool.Package"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "root"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "My_Cool.Package" },
]
`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}

	expected := "package/pypi/my-cool-package?version=1.0.0"
	if edges[0].ChildKey != expected {
		t.Errorf("expected child key %s, got %s", expected, edges[0].ChildKey)
	}
}

func TestParseLockfileEditable(t *testing.T) {
	content := []byte(`
version = 1
requires-python = ">=3.9"

[[package]]
name = "some-lib"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "my-editable"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "some-lib" },
]
`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}

	if edges[0].ParentKey != "" {
		t.Errorf("editable package deps should be direct (empty parent), got %s", edges[0].ParentKey)
	}

	expected := "package/pypi/some-lib?version=1.0.0"
	if edges[0].ChildKey != expected {
		t.Errorf("expected child key %s, got %s", expected, edges[0].ChildKey)
	}
}

func TestParseLockfileInvalidTOML(t *testing.T) {
	content := []byte(`this is not valid { toml [[[`)

	_, err := ParseLockfile(content)
	if err == nil {
		t.Fatal("expected error for invalid TOML, got nil")
	}
}

func TestParseLockfileNilContent(t *testing.T) {
	_, err := ParseLockfile(nil)
	if err == nil {
		t.Fatal("expected error for nil content, got nil")
	}

	_, err = ParseLockfile([]byte{})
	if err == nil {
		t.Fatal("expected error for empty content, got nil")
	}
}

func TestParseLockfileOptionalDeps(t *testing.T) {
	content := []byte(`
version = 1
requires-python = ">=3.9"

[[package]]
name = "some-lib"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[package.optional-dependencies]
extra1 = [
    { name = "opt-dep-a" },
]

[[package]]
name = "opt-dep-a"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "root"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "some-lib" },
]
`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	directDeps := make(map[string]bool)
	transitiveDeps := make(map[string]string)

	for _, edge := range edges {
		if edge.ParentKey == "" {
			directDeps[edge.ChildKey] = true
		} else {
			transitiveDeps[edge.ChildKey] = edge.ParentKey
		}
	}

	someLibKey := "package/pypi/some-lib?version=1.0.0"
	optDepKey := "package/pypi/opt-dep-a?version=2.0.0"

	if !directDeps[someLibKey] {
		t.Errorf("some-lib should be a direct dep")
	}

	if transitiveDeps[optDepKey] != someLibKey {
		t.Errorf("opt-dep-a should be transitive under some-lib, got parent %s", transitiveDeps[optDepKey])
	}
}

func TestParseLockfileDevDeps(t *testing.T) {
	content := []byte(`
version = 1
requires-python = ">=3.9"

[[package]]
name = "pluggy"
version = "1.5.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "pluggy" },
]

[[package]]
name = "requests"
version = "2.32.5"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "root"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]
`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requestsKey := "package/pypi/requests?version=2.32.5"
	pytestKey := "package/pypi/pytest?version=8.0.0"
	pluggyKey := "package/pypi/pluggy?version=1.5.0"

	edgeMap := make(map[string]models.DepsTreeEdge)
	for _, edge := range edges {
		edgeMap[edge.ParentKey+"|"+edge.ChildKey] = edge
	}

	// requests: direct prod dep
	reqEdge, ok := edgeMap["|"+requestsKey]
	if !ok {
		t.Fatal("requests should be a direct dep")
	}
	if reqEdge.Dev {
		t.Error("requests should have Dev=false")
	}

	// pytest: direct dev dep
	pytestEdge, ok := edgeMap["|"+pytestKey]
	if !ok {
		t.Fatal("pytest should be a direct dep")
	}
	if !pytestEdge.Dev {
		t.Error("pytest should have Dev=true")
	}

	// pluggy: transitive dep of pytest → should be Dev=true
	pluggyEdge, ok := edgeMap[pytestKey+"|"+pluggyKey]
	if !ok {
		t.Fatal("pluggy should be a transitive dep of pytest")
	}
	if !pluggyEdge.Dev {
		t.Error("pluggy (transitive dev dep) should have Dev=true")
	}
}

func TestParseLockfileDevAndProdOverlap(t *testing.T) {
	content := []byte(`
version = 1
requires-python = ">=3.9"

[[package]]
name = "shared-lib"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "shared-lib" },
]

[[package]]
name = "requests"
version = "2.32.5"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "shared-lib" },
]

[[package]]
name = "root"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]
`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sharedKey := "package/pypi/shared-lib?version=1.0.0"
	pytestKey := "package/pypi/pytest?version=8.0.0"
	requestsKey := "package/pypi/requests?version=2.32.5"

	for _, edge := range edges {
		if edge.ChildKey != sharedKey {
			continue
		}
		switch edge.ParentKey {
		case requestsKey:
			if edge.Dev {
				t.Error("shared-lib under requests (prod path) should have Dev=false")
			}
		case pytestKey:
			if edge.Dev {
				t.Error("shared-lib under pytest should have Dev=false (reachable via prod path)")
			}
		}
	}

	// pytest itself should still be dev
	for _, edge := range edges {
		if edge.ParentKey == "" && edge.ChildKey == pytestKey {
			if !edge.Dev {
				t.Error("pytest should have Dev=true")
			}
		}
	}
}
