package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
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

func TestBuildSBOMJSON_UnknownFormat(t *testing.T) {
	_, err := buildSBOMJSON("turtle", "source/x", nil)
	if err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
	if !strings.Contains(err.Error(), "turtle") {
		t.Errorf("error should mention the bad format, got %q", err)
	}
}
