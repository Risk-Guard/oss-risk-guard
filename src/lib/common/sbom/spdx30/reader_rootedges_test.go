package spdx30

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// foreignDoc builds a minimal third-party SPDX 3 document: a root package, a set
// of purl-bearing packages, and the given relationships.
func foreignDoc(pkgs map[string]string, rels [][3]string) []byte {
	var graph strings.Builder
	graph.WriteString(`{"type":"SpdxDocument","spdxId":"doc","rootElement":["root"]},`)
	graph.WriteString(`{"type":"software_Package","spdxId":"root","name":"main"}`)
	for id, purl := range pkgs {
		graph.WriteString(`,{"type":"software_Package","spdxId":"` + id + `","name":"` + id +
			`","software_packageUrl":"` + purl + `"}`)
	}
	for _, r := range rels {
		graph.WriteString(`,{"type":"Relationship","relationshipType":"` + r[0] +
			`","from":"` + r[1] + `","to":["` + r[2] + `"]}`)
	}
	return []byte(`{"@context":"` + Context + `","@graph":[` + graph.String() + `]}`)
}

func keysOf(t *testing.T, raw []byte) []string {
	t.Helper()
	keys, err := ReadDirectDeps(raw)
	require.NoError(t, err)
	return keys
}

func TestRootChildIDs_ContainsOnlyRootEdgePromotesTopLevel(t *testing.T) {
	raw := foreignDoc(
		map[string]string{
			"requests": "pkg:pypi/requests@2.32.5",
			"certifi":  "pkg:pypi/certifi@2026.1.4",
			"idna":     "pkg:pypi/idna@3.11",
		},
		[][3]string{
			{RelationshipContains, "root", "requests"},
			{RelationshipDependsOn, "requests", "certifi"},
			{RelationshipDependsOn, "requests", "idna"},
		},
	)

	assert.ElementsMatch(t,
		[]string{"package/pypi/requests?version=2.32.5"},
		keysOf(t, raw),
		"root-contains promotes the top-level package without pulling in its transitives")
}

func TestRootChildIDs_RootDependsOnSuppressesFlatContainsList(t *testing.T) {
	raw := foreignDoc(
		map[string]string{
			"express":     "pkg:npm/express@4.18.1",
			"body-parser": "pkg:npm/body-parser@1.20.1",
			"self":        "pkg:npm/my-app@1.0.0",
		},
		[][3]string{
			{RelationshipDependsOn, "root", "express"},
			{RelationshipDependsOn, "express", "body-parser"},
			{RelationshipContains, "root", "express"},
			{RelationshipContains, "root", "body-parser"},
			{RelationshipContains, "root", "self"},
		},
	)

	assert.Equal(t,
		[]string{"package/npm/express?version=4.18.1"},
		keysOf(t, raw),
		"a root dependsOn edge wins; the flat contains list, project package included, is ignored")
}

func TestRootChildIDs_ContainsDuplicateOfDependsOnTargetIsDropped(t *testing.T) {
	raw := foreignDoc(
		map[string]string{
			"lodash-lock":      "pkg:npm/lodash@4.17.23",
			"lodash-installed": "pkg:npm/lodash@4.17.23?source=UNKNOWN",
		},
		[][3]string{
			{RelationshipDependsOn, "root", "lodash-lock"},
			{RelationshipContains, "root", "lodash-installed"},
		},
	)

	assert.Equal(t,
		[]string{"package/npm/lodash?version=4.17.23"},
		keysOf(t, raw),
		"the same package enumerated twice resolves to one key")
}

func TestRootChildIDs_NoRootEdgesFallsBackToAllPackages(t *testing.T) {
	raw := foreignDoc(
		map[string]string{
			"rake":  "pkg:gem/rake@13.3.1",
			"rspec": "pkg:gem/rspec@3.13.2",
		},
		nil,
	)

	assert.ElementsMatch(t,
		[]string{"package/rubygems/rake?version=13.3.1", "package/rubygems/rspec?version=3.13.2"},
		keysOf(t, raw),
		"a document with no root edges audits every package rather than none")
}

func TestRootChildIDs_DependsOnRootEdgeIgnoresUnrelatedContains(t *testing.T) {
	raw := foreignDoc(
		map[string]string{
			"express":     "pkg:npm/express@4.18.1",
			"body-parser": "pkg:npm/body-parser@1.20.1",
		},
		[][3]string{
			{RelationshipDependsOn, "root", "express"},
			{RelationshipDependsOn, "express", "body-parser"},
			{RelationshipContains, "root", "body-parser"},
		},
	)

	assert.Equal(t,
		[]string{"package/npm/express?version=4.18.1"},
		keysOf(t, raw),
		"a transitive listed under root-contains stays transitive")
}
