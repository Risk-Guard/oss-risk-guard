package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// When package.json + package-lock.json are both present, lockfile edges must
// carry the manifest Location (file + line of the dep in package.json) so SARIF
// physicalLocation can be populated downstream.
//   - Direct edges (ParentKey == "") carry the location of that dep's line.
//   - Transitive edges inherit the location of the direct ancestor that pulled
//     them in.
func TestParseManifest_LockfileEdges_CarryManifestLocation(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{
  "name": "demo",
  "dependencies": {
    "react": "^19.2.5",
    "next": "^16.2.4"
  },
  "devDependencies": {
    "prettier": "^3.8.3"
  }
}`
	// react (direct) → scheduler (transitive)
	// next (direct, no transitive deps in this fixture)
	// prettier (dev, direct)
	lockJSON := `{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo",
      "dependencies": {"react": "^19.2.5", "next": "^16.2.4"},
      "devDependencies": {"prettier": "^3.8.3"}
    },
    "node_modules/react": {
      "version": "19.2.5",
      "dependencies": {"scheduler": "^0.27.0"}
    },
    "node_modules/scheduler": {"version": "0.27.0"},
    "node_modules/next": {"version": "16.2.4"},
    "node_modules/prettier": {"version": "3.8.3", "dev": true}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockJSON), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	detected := models.DetectedManifest{
		Ecosystem: "npm",
		Paths:     []string{"package.json"},
		Lockfile:  strPtr("package-lock.json"),
	}

	result, err := ParseManifest(detected, dir)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(result.LockfileDependencies) == 0 {
		t.Fatalf("expected lockfile edges, got none")
	}

	// Lines in pkgJSON above (1-indexed):
	//   line 4: "react": "^19.2.5"
	//   line 5: "next":  "^16.2.4"
	//   line 8: "prettier": "^3.8.3"
	wantLine := map[string]int{
		"package/npm/react?version=19.2.5":     4,
		"package/npm/next?version=16.2.4":      5,
		"package/npm/prettier?version=3.8.3":   8,
		"package/npm/scheduler?version=0.27.0": 4, // inherited from react
	}

	byChild := map[string]models.DepsTreeEdge{}
	for _, e := range result.LockfileDependencies {
		// For transitives there may be multiple edges into the same child via
		// different parents; in this fixture scheduler has a single parent.
		byChild[e.ChildKey] = e
	}

	for key, want := range wantLine {
		e, ok := byChild[key]
		if !ok {
			t.Errorf("missing edge for %s", key)
			continue
		}
		if e.Location == nil || e.Location.File == nil {
			t.Errorf("%s: expected Location with File set, got %+v", key, e.Location)
			continue
		}
		if *e.Location.File != "package.json" {
			t.Errorf("%s: File = %q, want package.json", key, *e.Location.File)
		}
		gotLine := -1
		if e.Location.LineNumber != nil {
			gotLine = *e.Location.LineNumber
		}
		if gotLine != want {
			t.Errorf("%s: LineNumber = %d, want %d", key, gotLine, want)
		}
	}
}

func strPtr(s string) *string { return &s }

func TestParseManifest_PrivateTrue(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"name": "my-private-app",
		"private": true,
		"dependencies": {
			"express": "^4.18.0"
		}
	}`
	err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0o600)
	if err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	detected := models.DetectedManifest{
		Ecosystem: "npm",
		Paths:     []string{"package.json"},
	}

	result, err := ParseManifest(detected, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Private {
		t.Error("expected result.Private to be true")
	}
}

func TestParseManifest_PrivateFalse(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"name": "my-public-lib",
		"dependencies": {
			"lodash": "^4.17.0"
		}
	}`
	err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0o600)
	if err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	detected := models.DetectedManifest{
		Ecosystem: "npm",
		Paths:     []string{"package.json"},
	}

	result, err := ParseManifest(detected, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Private {
		t.Error("expected result.Private to be false when not specified")
	}
}
