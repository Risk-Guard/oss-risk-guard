package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

func TestBuildSBOMJSON_SPDX(t *testing.T) {
	nodes := []depsgraph.SBOMNode{{Key: "source/example.com/repo"}}
	data, err := buildSBOMJSON(sbomFormatSPDX, "source/example.com/repo", nodes)
	if err != nil {
		t.Fatalf("buildSBOMJSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	ctx, _ := parsed["@context"].(string)
	if !strings.HasPrefix(ctx, "https://spdx.org/") {
		t.Errorf("expected @context to be an SPDX URL, got %q", ctx)
	}
	if _, ok := parsed["@graph"].([]any); !ok {
		t.Error("expected @graph array in SPDX output")
	}
}

func TestBuildSBOMJSON_CycloneDX(t *testing.T) {
	eco, name, ver := "npm", "lodash", "4.17.21"
	nodes := []depsgraph.SBOMNode{
		{Key: "source/example.com/repo"},
		{Key: "package/npm/lodash?version=4.17.21", Ecosystem: &eco, PackageName: &name, PackageVersion: &ver},
	}
	data, err := buildSBOMJSON(sbomFormatCycloneDX, "source/example.com/repo", nodes)
	if err != nil {
		t.Fatalf("buildSBOMJSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", parsed["bomFormat"])
	}
	if parsed["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", parsed["specVersion"])
	}
	components, ok := parsed["components"].([]any)
	if !ok || len(components) == 0 {
		t.Errorf("expected non-empty components array, got %v", parsed["components"])
	}
}

func TestBuildSBOMNodes_DedupesDuplicateEdges(t *testing.T) {
	root := "source/repo"
	lodash := "package/npm/lodash"
	file := "package.json"
	line := 12

	// Same child appears twice in two edges from the root — a real case when
	// multiple manifests in a polyglot repo declare the same package.
	edges := []models.DepsTreeEdge{
		{
			ParentKey: root, ChildKey: lodash, Ecosystem: "npm",
			Location: &models.LocationInfo{File: &file, LineNumber: &line},
		},
		{ParentKey: root, ChildKey: lodash, Ecosystem: "npm"},
	}

	nodes := buildSBOMNodes(root, edges)

	var rootNode *depsgraph.SBOMNode
	for i := range nodes {
		if nodes[i].Key == root {
			rootNode = &nodes[i]
		}
	}
	if rootNode == nil {
		t.Fatal("root node missing from buildSBOMNodes output")
	}
	if len(rootNode.Deps) != 1 || rootNode.Deps[0] != lodash {
		t.Errorf("expected one deduped Deps entry %q, got %v", lodash, rootNode.Deps)
	}

	// The first non-nil Location should win; verify the child has it set.
	var child *depsgraph.SBOMNode
	for i := range nodes {
		if nodes[i].Key == lodash {
			child = &nodes[i]
		}
	}
	if child == nil {
		t.Fatal("lodash child node missing")
	}
	if child.Location == nil || child.Location.File == nil || *child.Location.File != file {
		t.Errorf("expected Location {%q,:%d} on child, got %+v", file, line, child.Location)
	}
}

func TestInferSBOMFormat(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"sbom.spdx.json", sbomFormatSPDX},
		{"out/bom.SPDX.JSON", sbomFormatSPDX},
		{"artifact.spdx", sbomFormatSPDX},
		{"sbom.cdx.json", sbomFormatCycloneDX},
		{"out/sbom.CDX.json", sbomFormatCycloneDX},
		{"artifact.cdx", sbomFormatCycloneDX},
		{"sbom.bom.json", sbomFormatCycloneDX},
		{"sbom.json", sbomFormatSPDX}, // no hint → default
		{"-", sbomFormatSPDX},         // stdout → default
		{"weird.txt", sbomFormatSPDX}, // unknown → default
	}
	for _, tc := range cases {
		if got := inferSBOMFormat(tc.path); got != tc.want {
			t.Errorf("inferSBOMFormat(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestBuildSBOMJSON_UnknownFormat(t *testing.T) {
	_, err := buildSBOMJSON("turtle", "source/x", nil)
	if err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
	if !strings.Contains(err.Error(), "turtle") {
		t.Errorf("error should mention the bad format, got %q", err)
	}
}
