package bun

import (
	"slices"
	"testing"
)

func TestParseLockfileSimple(t *testing.T) {
	// Intentionally includes a // comment and a trailing comma to exercise
	// jsonc.ToJSON normalization.
	content := []byte(`{
		"lockfileVersion": 1,
		// root workspace
		"workspaces": {
			"": {
				"name": "app",
				"dependencies": {
					"chalk": "^5.3.0",
				},
			},
		},
		"packages": {
			"chalk": ["chalk@5.4.1", "", { "dependencies": { "ansi-styles": "^6.2.1" } }, "sha512-a"],
			"ansi-styles": ["ansi-styles@6.2.1", "", {}, "sha512-b"]
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	directDeps := make(map[string]bool)
	childParents := make(map[string][]string)
	for _, e := range edges {
		if e.ParentKey == "" {
			directDeps[e.ChildKey] = true
		} else {
			childParents[e.ChildKey] = append(childParents[e.ChildKey], e.ParentKey)
		}
	}

	chalkKey := "package/npm/chalk?version=5.4.1"
	ansiKey := "package/npm/ansi-styles?version=6.2.1"

	if !directDeps[chalkKey] {
		t.Errorf("chalk should be a direct dep; got %v", directDeps)
	}
	if directDeps[ansiKey] {
		t.Error("ansi-styles should not be a direct dep")
	}
	if !slices.Contains(childParents[ansiKey], chalkKey) {
		t.Errorf("expected chalk -> ansi-styles edge; got parents %v", childParents[ansiKey])
	}
}

func TestParseLockfileDevFlag(t *testing.T) {
	// typescript is a root devDependency; its transitive dep is-number must
	// inherit Dev=true. shared is both a prod dep (of chalk) and reachable via
	// dev, so it must resolve Dev=false.
	content := []byte(`{
		"lockfileVersion": 1,
		"workspaces": {
			"": {
				"name": "app",
				"dependencies": { "chalk": "^5" },
				"devDependencies": { "typescript": "^5" }
			}
		},
		"packages": {
			"chalk": ["chalk@5.4.1", "", { "dependencies": { "shared": "^1" } }, "sha512-a"],
			"typescript": ["typescript@5.4.0", "", { "dependencies": { "is-number": "^7", "shared": "^1" } }, "sha512-b"],
			"is-number": ["is-number@7.0.0", "", {}, "sha512-c"],
			"shared": ["shared@1.0.0", "", {}, "sha512-d"]
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dev := make(map[string]bool)
	for _, e := range edges {
		// A child is dev only if ALL its incoming edges are dev; PropagateDevFlag
		// sets every edge to a child consistently, so record the last seen.
		dev[e.ChildKey] = e.Dev
	}

	tsKey := "package/npm/typescript?version=5.4.0"
	isNumberKey := "package/npm/is-number?version=7.0.0"
	sharedKey := "package/npm/shared?version=1.0.0"

	if !dev[tsKey] {
		t.Error("typescript should be Dev=true")
	}
	if !dev[isNumberKey] {
		t.Error("is-number should inherit Dev=true")
	}
	if dev[sharedKey] {
		t.Error("shared is reachable via prod (chalk), should be Dev=false")
	}
}

func TestParseLockfileNpmAlias(t *testing.T) {
	// Alias key react-is-18 with descriptor react-is@18.3.1: identity must be
	// the real name; the alias label must not leak.
	content := []byte(`{
		"lockfileVersion": 1,
		"workspaces": {
			"": {
				"name": "app",
				"dependencies": { "react-is-18": "npm:react-is@18.3.1" }
			}
		},
		"packages": {
			"react-is-18": ["react-is@18.3.1", "", {}, "sha512-a"]
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	directDeps := make(map[string]bool)
	for _, e := range edges {
		if e.ParentKey == "" {
			directDeps[e.ChildKey] = true
		}
	}

	if !directDeps["package/npm/react-is?version=18.3.1"] {
		t.Errorf("alias should resolve to react-is@18.3.1; got %v", directDeps)
	}
	if directDeps["package/npm/react-is-18?version=18.3.1"] {
		t.Error("alias label react-is-18 must not leak into identity")
	}
}

func TestParseLockfileNestedVersionConflict(t *testing.T) {
	// chalk nests its own ansi-styles@6.2.1 (key chalk/ansi-styles); another
	// consumer resolves the top-level ansi-styles@4.3.0.
	content := []byte(`{
		"lockfileVersion": 1,
		"workspaces": {
			"": {
				"name": "app",
				"dependencies": { "chalk": "^5", "wrap-ansi": "^7" }
			}
		},
		"packages": {
			"chalk": ["chalk@5.4.1", "", { "dependencies": { "ansi-styles": "^6.2.1" } }, "sha512-a"],
			"chalk/ansi-styles": ["ansi-styles@6.2.1", "", {}, "sha512-b"],
			"wrap-ansi": ["wrap-ansi@7.0.0", "", { "dependencies": { "ansi-styles": "^4.3.0" } }, "sha512-c"],
			"ansi-styles": ["ansi-styles@4.3.0", "", {}, "sha512-d"]
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	childParents := make(map[string][]string)
	for _, e := range edges {
		childParents[e.ChildKey] = append(childParents[e.ChildKey], e.ParentKey)
	}

	chalkKey := "package/npm/chalk?version=5.4.1"
	wrapKey := "package/npm/wrap-ansi?version=7.0.0"
	ansi6Key := "package/npm/ansi-styles?version=6.2.1"
	ansi4Key := "package/npm/ansi-styles?version=4.3.0"

	if !slices.Contains(childParents[ansi6Key], chalkKey) {
		t.Errorf("chalk should get nested ansi-styles@6.2.1; got %v", childParents[ansi6Key])
	}
	if !slices.Contains(childParents[ansi4Key], wrapKey) {
		t.Errorf("wrap-ansi should get top-level ansi-styles@4.3.0; got %v", childParents[ansi4Key])
	}
}

func TestParseLockfileScoped(t *testing.T) {
	content := []byte(`{
		"lockfileVersion": 1,
		"workspaces": {
			"": {
				"name": "app",
				"dependencies": { "@babel/core": "^7.24.0" }
			}
		},
		"packages": {
			"@babel/core": ["@babel/core@7.24.0", "", { "dependencies": { "@babel/types": "^7.24.0" } }, "sha512-a"],
			"@babel/types": ["@babel/types@7.24.0", "", {}, "sha512-b"]
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	directDeps := make(map[string]bool)
	childParents := make(map[string][]string)
	for _, e := range edges {
		if e.ParentKey == "" {
			directDeps[e.ChildKey] = true
		} else {
			childParents[e.ChildKey] = append(childParents[e.ChildKey], e.ParentKey)
		}
	}

	coreKey := "package/npm/@babel/core?version=7.24.0"
	typesKey := "package/npm/@babel/types?version=7.24.0"

	if !directDeps[coreKey] {
		t.Errorf("@babel/core should be a direct dep; got %v", directDeps)
	}
	if !slices.Contains(childParents[typesKey], coreKey) {
		t.Errorf("@babel/core -> @babel/types edge expected; got %v", childParents[typesKey])
	}
}

func TestParseLockfileMultiWorkspace(t *testing.T) {
	content := []byte(`{
		"lockfileVersion": 1,
		"workspaces": {
			"": {
				"name": "root",
				"dependencies": { "chalk": "^5" }
			},
			"packages/sub": {
				"name": "sub",
				"dependencies": { "is-number": "^7" }
			}
		},
		"packages": {
			"chalk": ["chalk@5.4.1", "", {}, "sha512-a"],
			"is-number": ["is-number@7.0.0", "", {}, "sha512-b"]
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	directDeps := make(map[string]bool)
	for _, e := range edges {
		if e.ParentKey == "" {
			directDeps[e.ChildKey] = true
		}
	}

	if !directDeps["package/npm/chalk?version=5.4.1"] {
		t.Error("root workspace chalk should be direct")
	}
	if !directDeps["package/npm/is-number?version=7.0.0"] {
		t.Error("member workspace is-number should be direct")
	}
}

func TestParseLockfilePeerExcludedAndSelfRefSkipped(t *testing.T) {
	// peerDependencies produce no transitive edge; a workspace self-reference
	// (name present only in workspaces, not packages) is skipped as a direct dep.
	content := []byte(`{
		"lockfileVersion": 1,
		"workspaces": {
			"": {
				"name": "app",
				"dependencies": { "chalk": "^5", "sub": "workspace:*" }
			},
			"packages/sub": { "name": "sub" }
		},
		"packages": {
			"chalk": ["chalk@5.4.1", "", { "peerDependencies": { "react": "^18" } }, "sha512-a"]
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, e := range edges {
		if e.ChildKey == "package/npm/react?version=18" || e.ChildKey == "package/npm/react" {
			t.Errorf("peerDependency react must not produce an edge: %+v", e)
		}
		if e.ChildKey == "package/npm/sub" {
			t.Errorf("workspace self-ref sub must not produce an edge: %+v", e)
		}
	}

	directDeps := make(map[string]bool)
	for _, e := range edges {
		if e.ParentKey == "" {
			directDeps[e.ChildKey] = true
		}
	}
	if !directDeps["package/npm/chalk?version=5.4.1"] {
		t.Error("chalk should still be a direct dep")
	}
}

func TestParseLockfileEmpty(t *testing.T) {
	_, err := ParseLockfile([]byte{})
	if err == nil {
		t.Error("empty content should error")
	}
}

func TestParseLockfileNoGraph(t *testing.T) {
	_, err := ParseLockfile([]byte(`{"lockfileVersion":1}`))
	if err == nil {
		t.Error("lockfile with no workspaces and no packages should error")
	}
}

func TestParseLockfileMalformedEntrySkipped(t *testing.T) {
	// An empty-array value and a descriptor with no '@' must be skipped without
	// panicking, while the valid entry still parses.
	content := []byte(`{
		"lockfileVersion": 1,
		"workspaces": {
			"": { "name": "app", "dependencies": { "chalk": "^5" } }
		},
		"packages": {
			"broken": [],
			"noat": ["noatsign", "", {}, "sha512-x"],
			"chalk": ["chalk@5.4.1", "", {}, "sha512-a"]
		}
	}`)

	edges, err := ParseLockfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	directDeps := make(map[string]bool)
	for _, e := range edges {
		if e.ParentKey == "" {
			directDeps[e.ChildKey] = true
		}
	}
	if !directDeps["package/npm/chalk?version=5.4.1"] {
		t.Errorf("valid chalk entry should survive malformed siblings; got %v", directDeps)
	}
}

func TestParseLockfileBinaryGuard(t *testing.T) {
	// bun.lockb-only repos: content whose first non-whitespace byte is not '{'
	// must return (nil, nil), NOT an error — otherwise a spurious CRITICAL
	// SOURCE_MALFORMED_METADATA finding regresses those repos.
	cases := [][]byte{
		{0x00, 0x01, 0x02},
		[]byte("bun.lockb binary header..."),
		{' ', '\n', 0xFF},
	}
	for i, content := range cases {
		edges, err := ParseLockfile(content)
		if err != nil {
			t.Errorf("case %d: binary content must not error, got %v", i, err)
		}
		if edges != nil {
			t.Errorf("case %d: binary content must return nil edges, got %v", i, edges)
		}
	}
}
