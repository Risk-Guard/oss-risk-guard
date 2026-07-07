package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/fatih/color"
)

// treeFixture builds a Summary with a nested graph across two ecosystems, used
// by the tree tests:
//
//	root
//	│
//	npm
//	├── express@5.2.2 (package.json:12)
//	│   └── ms@2.1.3
//	│       └── tiny@1.0.0
//	└── react@19.2.7
//	    └── scheduler@0.27.0
//	        └── ms@2.1.3   (shared, non-leaf -> deduped)
//	pypi
//	└── requests@2.28.0 (requirements.txt:1)
func treeFixture() *sbom.Summary {
	pkgJSON := "package.json"
	reqTxt := "requirements.txt"
	line, reqLine := 12, 1
	return &sbom.Summary{
		Format:      "SPDX",
		SpecVersion: "3.0.1",
		Tool:        "risk-guard",
		RootName:    "source/example.com/demo",
		RootDeps:    []string{"k:express", "k:react", "k:requests"},
		Packages: []sbom.Package{
			{Key: "k:express", Ecosystem: "npm", Name: "express", Version: "5.2.2", Deps: []string{"k:ms"}, Location: &models.LocationInfo{File: &pkgJSON, LineNumber: &line}},
			{Key: "k:react", Ecosystem: "npm", Name: "react", Version: "19.2.7", Deps: []string{"k:scheduler"}},
			{Key: "k:ms", Ecosystem: "npm", Name: "ms", Version: "2.1.3", Deps: []string{"k:tiny"}},
			{Key: "k:scheduler", Ecosystem: "npm", Name: "scheduler", Version: "0.27.0", Deps: []string{"k:ms"}},
			{Key: "k:tiny", Ecosystem: "npm", Name: "tiny", Version: "1.0.0"},
			{Key: "k:requests", Ecosystem: "pypi", Name: "requests", Version: "2.28.0", Location: &models.LocationInfo{File: &reqTxt, LineNumber: &reqLine}},
		},
	}
}

func plainViewOutput(t *testing.T, summary *sbom.Summary, maxDepth int) string {
	t.Helper()
	prev := color.NoColor
	t.Cleanup(func() { color.NoColor = prev })
	color.NoColor = true // assert on plain text

	var buf bytes.Buffer
	printSBOMSummary(&buf, "sbom.spdx.json", summary, maxDepth)
	return buf.String()
}

func TestPrintSBOMSummary_FullTree(t *testing.T) {
	out := plainViewOutput(t, treeFixture(), 0)

	// Header block.
	for _, want := range []string{"sbom.spdx.json", "SPDX 3.0.1", "risk-guard", "Packages: 6", "source/example.com/demo"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}

	// Top-level ecosystem headers, npm before pypi.
	npmAt := strings.Index(out, "\nnpm\n")
	pypiAt := strings.Index(out, "\npypi\n")
	if npmAt < 0 || pypiAt < 0 {
		t.Fatalf("expected npm and pypi ecosystem headers\n---\n%s", out)
	}
	if npmAt > pypiAt {
		t.Errorf("expected npm group before pypi group\n---\n%s", out)
	}

	// Tree connectors and nesting.
	wantLines := []string{
		"├── express@5.2.2  package.json:12",
		"│   └── ms@2.1.3",
		"│       └── tiny@1.0.0",
		"└── react@19.2.7",
		"    └── scheduler@0.27.0",
		"        └── ms@2.1.3 (deduped)",
		"└── requests@2.28.0  requirements.txt:1",
	}
	for _, want := range wantLines {
		if !strings.Contains(out, want) {
			t.Errorf("tree missing line %q\n---\n%s", want, out)
		}
	}

	// requests must sit under the pypi header, not the npm one.
	if idx := strings.Index(out, "requests@2.28.0"); idx < pypiAt {
		t.Errorf("requests should appear under the pypi group\n---\n%s", out)
	}

	// ms is expanded once (under express) and deduped once (under scheduler):
	// tiny must appear exactly once.
	if got := strings.Count(out, "tiny@1.0.0"); got != 1 {
		t.Errorf("tiny should appear once (deduped subtree), got %d\n---\n%s", got, out)
	}
}

func TestPrintSBOMSummary_MaxDepth1(t *testing.T) {
	out := plainViewOutput(t, treeFixture(), 1)

	// Only direct deps, each marked with its hidden child count.
	if !strings.Contains(out, "├── express@5.2.2  package.json:12 (+1 deps)") {
		t.Errorf("expected express capped at depth 1 with (+1 deps)\n---\n%s", out)
	}
	if !strings.Contains(out, "└── react@19.2.7 (+1 deps)") {
		t.Errorf("expected react capped at depth 1 with (+1 deps)\n---\n%s", out)
	}
	// Transitives must not appear.
	for _, hidden := range []string{"ms@2.1.3", "tiny@1.0.0", "scheduler@0.27.0"} {
		if strings.Contains(out, hidden) {
			t.Errorf("depth-1 view should hide %q\n---\n%s", hidden, out)
		}
	}
}

func TestPrintSBOMSummary_MaxDepth2(t *testing.T) {
	out := plainViewOutput(t, treeFixture(), 2)

	if !strings.Contains(out, "│   └── ms@2.1.3 (+1 deps)") {
		t.Errorf("expected ms shown at depth 2 with its child hidden\n---\n%s", out)
	}
	if !strings.Contains(out, "    └── scheduler@0.27.0 (+1 deps)") {
		t.Errorf("expected scheduler shown at depth 2 with its child hidden\n---\n%s", out)
	}
	if strings.Contains(out, "tiny@1.0.0") {
		t.Errorf("depth-2 view should hide tiny@1.0.0 (depth 3)\n---\n%s", out)
	}
}

func TestPrintSBOMSummary_NoDependencies(t *testing.T) {
	summary := &sbom.Summary{Format: "CycloneDX", SpecVersion: "1.6", Tool: "risk-guard", RootName: "source/x"}
	out := plainViewOutput(t, summary, 0)

	if !strings.Contains(out, "Packages: 0") {
		t.Errorf("expected zero-package count\n---\n%s", out)
	}
	if !strings.Contains(out, "(no dependencies)") {
		t.Errorf("expected empty-state note\n---\n%s", out)
	}
}
