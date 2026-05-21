package npm

import (
	"slices"
	"testing"
)

func TestParseLockfileV3(t *testing.T) {
	content := []byte(`{
		"name": "test-project",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "test-project",
				"dependencies": {
					"express": "^4.18.0"
				},
				"devDependencies": {
					"typescript": "^5.0.0"
				}
			},
			"node_modules/express": {
				"version": "4.18.2",
				"dependencies": {
					"body-parser": "1.20.1"
				}
			},
			"node_modules/body-parser": {
				"version": "1.20.1",
				"dependencies": {
					"bytes": "3.1.2"
				}
			},
			"node_modules/bytes": {
				"version": "3.1.2"
			},
			"node_modules/typescript": {
				"version": "5.0.4"
			}
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Build maps for easier testing
	directDeps := make(map[string]bool)
	transitiveDeps := make(map[string]string) // child -> parent

	for _, edge := range edges {
		if edge.ParentKey == "" {
			directDeps[edge.ChildKey] = true
		} else {
			transitiveDeps[edge.ChildKey] = edge.ParentKey
		}
	}

	// Check direct deps (with versions)
	if !directDeps["package/npm/express?version=4.18.2"] {
		t.Error("express?version=4.18.2 should be a direct dep")
	}
	if !directDeps["package/npm/typescript?version=5.0.4"] {
		t.Error("typescript?version=5.0.4 should be a direct dep")
	}

	// Check transitive deps (with versions)
	if transitiveDeps["package/npm/body-parser?version=1.20.1"] != "package/npm/express?version=4.18.2" {
		t.Errorf("body-parser parent should be express?version=4.18.2, got %s", transitiveDeps["package/npm/body-parser?version=1.20.1"])
	}
	if transitiveDeps["package/npm/bytes?version=3.1.2"] != "package/npm/body-parser?version=1.20.1" {
		t.Errorf("bytes parent should be body-parser?version=1.20.1, got %s", transitiveDeps["package/npm/bytes?version=3.1.2"])
	}

	// bytes should NOT be a direct dep (it's hoisted but transitive)
	if directDeps["package/npm/bytes?version=3.1.2"] {
		t.Error("bytes should not be a direct dep")
	}
}

func TestParseLockfileV1(t *testing.T) {
	content := []byte(`{
		"name": "test-project",
		"lockfileVersion": 1,
		"dependencies": {
			"express": {
				"version": "4.18.2",
				"dependencies": {
					"body-parser": {
						"version": "1.20.1"
					}
				}
			}
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(edges))
	}

	// Find edges
	var expressEdge, bodyParserEdge *struct{ parent, child string }
	for _, e := range edges {
		if e.ChildKey == "package/npm/express?version=4.18.2" {
			expressEdge = &struct{ parent, child string }{e.ParentKey, e.ChildKey}
		}
		if e.ChildKey == "package/npm/body-parser?version=1.20.1" {
			bodyParserEdge = &struct{ parent, child string }{e.ParentKey, e.ChildKey}
		}
	}

	if expressEdge == nil || expressEdge.parent != "" {
		t.Error("express should be direct dep with empty parent")
	}
	if bodyParserEdge == nil || bodyParserEdge.parent != "package/npm/express?version=4.18.2" {
		t.Error("body-parser should have express as parent")
	}
}

func TestParseLockfileEmpty(t *testing.T) {
	content := []byte(`{
		"name": "empty-project",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "empty-project"
			}
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(edges) != 0 {
		t.Errorf("expected 0 edges for empty project, got %d", len(edges))
	}
}

func TestParseLockfileMultiVersion(t *testing.T) {
	// This tests npm's ability to have the same package at multiple versions
	// in nested node_modules directories. For example:
	// - node_modules/debug@4.3.4 (hoisted, used by express)
	// - node_modules/some-old-pkg/node_modules/debug@2.6.9 (nested, older version)
	content := []byte(`{
		"name": "multi-version-test",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "multi-version-test",
				"dependencies": {
					"express": "^4.18.0",
					"some-old-pkg": "^1.0.0"
				}
			},
			"node_modules/express": {
				"version": "4.18.2",
				"dependencies": {
					"debug": "4.3.4"
				}
			},
			"node_modules/debug": {
				"version": "4.3.4"
			},
			"node_modules/some-old-pkg": {
				"version": "1.0.0",
				"dependencies": {
					"debug": "2.6.9"
				}
			},
			"node_modules/some-old-pkg/node_modules/debug": {
				"version": "2.6.9"
			}
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Build edge map for verification
	edgeMap := make(map[string][]string) // child -> parents
	directDeps := make(map[string]bool)

	for _, edge := range edges {
		if edge.ParentKey == "" {
			directDeps[edge.ChildKey] = true
		} else {
			edgeMap[edge.ChildKey] = append(edgeMap[edge.ChildKey], edge.ParentKey)
		}
	}

	// express should depend on debug@4.3.4
	expressKey := "package/npm/express?version=4.18.2"
	debug4Key := "package/npm/debug?version=4.3.4"
	debug2Key := "package/npm/debug?version=2.6.9"
	someOldPkgKey := "package/npm/some-old-pkg?version=1.0.0"

	// Check that express -> debug@4.3.4
	if !slices.Contains(edgeMap[debug4Key], expressKey) {
		t.Errorf("expected express -> debug@4.3.4 edge, got parents: %v", edgeMap[debug4Key])
	}

	// Check that some-old-pkg -> debug@2.6.9
	if !slices.Contains(edgeMap[debug2Key], someOldPkgKey) {
		t.Errorf("expected some-old-pkg -> debug@2.6.9 edge, got parents: %v", edgeMap[debug2Key])
	}

	// debug@4.3.4 and debug@2.6.9 should NOT be direct deps
	if directDeps[debug4Key] {
		t.Error("debug@4.3.4 should not be a direct dep")
	}
	if directDeps[debug2Key] {
		t.Error("debug@2.6.9 should not be a direct dep")
	}
}

func TestParseLockfileWorkspaces(t *testing.T) {
	// npm workspaces have packages at paths like "packages/app-a" without node_modules/ prefix
	// The workspace packages are symlinked into node_modules/
	content := []byte(`{
		"name": "monorepo",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "monorepo",
				"workspaces": ["packages/*"]
			},
			"packages/app-a": {
				"name": "@mono/app-a",
				"version": "1.0.0",
				"dependencies": {
					"lodash": "^4.17.0"
				}
			},
			"node_modules/@mono/app-a": {
				"resolved": "packages/app-a",
				"link": true
			},
			"node_modules/lodash": {
				"version": "4.17.21"
			}
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Build edge map
	edgeMap := make(map[string][]string)
	directDeps := make(map[string]bool)
	for _, edge := range edges {
		if edge.ParentKey == "" {
			directDeps[edge.ChildKey] = true
		} else {
			edgeMap[edge.ChildKey] = append(edgeMap[edge.ChildKey], edge.ParentKey)
		}
	}

	// @mono/app-a should be a direct dep (it's a workspace package)
	appAKey := "package/npm/@mono/app-a?version=1.0.0"
	if !directDeps[appAKey] {
		t.Errorf("expected @mono/app-a to be a direct dep, got direct deps: %v", directDeps)
	}

	// lodash should be a transitive dep of @mono/app-a
	lodashKey := "package/npm/lodash?version=4.17.21"
	if !slices.Contains(edgeMap[lodashKey], appAKey) {
		t.Errorf("expected @mono/app-a -> lodash edge, got parents: %v", edgeMap[lodashKey])
	}
}

func TestParseLockfileV3_DevFlag(t *testing.T) {
	content := []byte(`{
		"name": "dev-flag-test",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "dev-flag-test",
				"dependencies": {
					"express": "^4.18.0"
				},
				"devDependencies": {
					"typescript": "^5.0.0"
				}
			},
			"node_modules/express": {
				"version": "4.18.2"
			},
			"node_modules/typescript": {
				"version": "5.0.4",
				"dev": true,
				"dependencies": {
					"is-number": "7.0.0"
				}
			},
			"node_modules/is-number": {
				"version": "7.0.0",
				"dev": true
			}
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	edgeByChild := make(map[string][]struct {
		parent string
		dev    bool
	})
	for _, edge := range edges {
		edgeByChild[edge.ChildKey] = append(edgeByChild[edge.ChildKey], struct {
			parent string
			dev    bool
		}{edge.ParentKey, edge.Dev})
	}

	tests := []struct {
		childKey   string
		wantDev    bool
		wantParent string
	}{
		{"package/npm/express?version=4.18.2", false, ""},
		{"package/npm/typescript?version=5.0.4", true, ""},
		{"package/npm/is-number?version=7.0.0", true, "package/npm/typescript?version=5.0.4"},
	}

	for _, tt := range tests {
		found := false
		for _, e := range edgeByChild[tt.childKey] {
			if e.parent == tt.wantParent {
				found = true
				if e.dev != tt.wantDev {
					t.Errorf("%s (parent=%s): got Dev=%v, want Dev=%v", tt.childKey, tt.wantParent, e.dev, tt.wantDev)
				}
			}
		}
		if !found {
			t.Errorf("%s: no edge with parent=%s found", tt.childKey, tt.wantParent)
		}
	}
}

func TestParseLockfileV1_DevFlag(t *testing.T) {
	content := []byte(`{
		"name": "dev-flag-test",
		"lockfileVersion": 1,
		"dependencies": {
			"express": {
				"version": "4.18.2"
			},
			"typescript": {
				"version": "5.0.4",
				"dev": true,
				"dependencies": {
					"is-number": {
						"version": "7.0.0",
						"dev": true
					}
				}
			}
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	edgeMap := make(map[string]struct {
		parent string
		dev    bool
	})
	for _, edge := range edges {
		edgeMap[edge.ChildKey] = struct {
			parent string
			dev    bool
		}{edge.ParentKey, edge.Dev}
	}

	tests := []struct {
		childKey string
		wantDev  bool
	}{
		{"package/npm/express?version=4.18.2", false},
		{"package/npm/typescript?version=5.0.4", true},
		{"package/npm/is-number?version=7.0.0", true},
	}

	for _, tt := range tests {
		e, ok := edgeMap[tt.childKey]
		if !ok {
			t.Errorf("%s: edge not found", tt.childKey)
			continue
		}
		if e.dev != tt.wantDev {
			t.Errorf("%s: got Dev=%v, want Dev=%v", tt.childKey, e.dev, tt.wantDev)
		}
	}
}

func TestParseLockfileNestedDirectDep(t *testing.T) {
	// Test case where a direct dependency also appears as a nested dependency
	// Only the root-level one should be marked as direct
	content := []byte(`{
		"name": "nested-direct-test",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "nested-direct-test",
				"dependencies": {
					"lodash": "^4.17.0",
					"some-pkg": "^1.0.0"
				}
			},
			"node_modules/lodash": {
				"version": "4.17.21"
			},
			"node_modules/some-pkg": {
				"version": "1.0.0",
				"dependencies": {
					"lodash": "3.10.1"
				}
			},
			"node_modules/some-pkg/node_modules/lodash": {
				"version": "3.10.1"
			}
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Count direct edges for each lodash version
	lodash4DirectCount := 0
	lodash3DirectCount := 0
	lodash4Key := "package/npm/lodash?version=4.17.21"
	lodash3Key := "package/npm/lodash?version=3.10.1"

	for _, edge := range edges {
		if edge.ParentKey == "" {
			if edge.ChildKey == lodash4Key {
				lodash4DirectCount++
			}
			if edge.ChildKey == lodash3Key {
				lodash3DirectCount++
			}
		}
	}

	// lodash@4.17.21 should be direct (it's at root level)
	if lodash4DirectCount != 1 {
		t.Errorf("expected exactly 1 direct edge for lodash@4.17.21, got %d", lodash4DirectCount)
	}

	// lodash@3.10.1 should NOT be direct (it's nested under some-pkg)
	if lodash3DirectCount != 0 {
		t.Errorf("expected 0 direct edges for lodash@3.10.1 (nested), got %d", lodash3DirectCount)
	}
}
