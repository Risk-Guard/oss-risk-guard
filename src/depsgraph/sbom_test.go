package depsgraph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEdgesToDepsMap_IncludesDevEdges(t *testing.T) {
	src := "source/github.com/example/repo"
	edges := []DepsTreeEdge{
		devEdge(src, "package/pypi/pytest"),
		devEdge("package/pypi/pytest", "package/pypi/pluggy"),
		edge(src, "package/npm/express"),
		edge("package/npm/express", "package/npm/debug"),
	}

	depsMap := edgesToDepsMap(edges)

	assert.Contains(t, depsMap[src], "package/pypi/pytest", "dev dep edge must be in depsMap")
	assert.Contains(t, depsMap[src], "package/npm/express", "prod dep edge must be in depsMap")
	assert.Contains(t, depsMap["package/pypi/pytest"], "package/pypi/pluggy", "transitive dev edge must be in depsMap")
	assert.Contains(t, depsMap["package/npm/express"], "package/npm/debug", "transitive prod edge must be in depsMap")
}

func TestEdgesToDepsMap_NoOrphans(t *testing.T) {
	// Every key from ExtractUniqueKeys (except root) must be referenced
	// as a child in depsMap. Orphans = SBOM packages with no inbound dependsOn.
	src := "source/github.com/example/repo"
	edges := []DepsTreeEdge{
		devEdge(src, "package/pypi/pytest"),
		devEdge("package/pypi/pytest", "package/pypi/pluggy"),
		devEdge("package/pypi/pluggy", "package/pypi/iniconfig"),
		edge(src, "package/npm/express"),
		edge("package/npm/express", "package/npm/debug"),
	}

	keys := ExtractUniqueKeys(src, edges)
	depsMap := edgesToDepsMap(edges)

	reachable := map[string]struct{}{src: {}}
	for _, children := range depsMap {
		for _, child := range children {
			reachable[child] = struct{}{}
		}
	}

	for _, key := range keys {
		assert.Contains(t, reachable, key,
			"%q in keys but not reachable via depsMap — would be orphan in SBOM", key)
	}
}

func TestParseKeyIdentity(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantEco string
		wantNam string
		wantVer string
	}{
		{
			name:    "simple package",
			key:     "package/npm/express",
			wantEco: "npm",
			wantNam: "express",
			wantVer: "",
		},
		{
			name:    "package with version",
			key:     "package/npm/express?version=4.18.2",
			wantEco: "npm",
			wantNam: "express",
			wantVer: "4.18.2",
		},
		{
			name:    "scoped package with version",
			key:     "package/npm/@scope/pkg?version=1.0.0",
			wantEco: "npm",
			wantNam: "@scope/pkg",
			wantVer: "1.0.0",
		},
		{
			name:    "source key returns empty",
			key:     "source/github.com/foo/bar",
			wantEco: "",
			wantNam: "",
			wantVer: "",
		},
		{
			name:    "empty string returns empty",
			key:     "",
			wantEco: "",
			wantNam: "",
			wantVer: "",
		},
		{
			name:    "package with trailing slash returns empty name",
			key:     "package/npm/",
			wantEco: "",
			wantNam: "",
			wantVer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eco, name, ver := parseKeyIdentity(tt.key)
			assert.Equal(t, tt.wantEco, eco)
			assert.Equal(t, tt.wantNam, name)
			assert.Equal(t, tt.wantVer, ver)
		})
	}
}
