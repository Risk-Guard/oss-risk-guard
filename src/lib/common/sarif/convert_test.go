package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

var testChecks = []dag_builder.CheckInfo{
	{
		Code:        "VULN_UNFIXED",
		Description: "Package has known unfixed vulnerabilities",
		Categories: map[category.RiskCategory]string{
			category.RiskCategorySecurityVulnerability: "",
		},
	},
	{
		Code:        "OUTDATED_DEPENDENCY",
		Description: "Dependency is outdated",
	},
	{
		Code:        "DEPRECATED_CHECK",
		Description: "Should be skipped",
		Deprecated:  true,
	},
}

func TestFromEvaluationResult_ReturnsValidSARIF(t *testing.T) {
	result := &policy.EvaluationResult{
		Status:   "PASS",
		Source:   "github.com/test/repo",
		Findings: []policy.Finding{},
	}

	report, err := FromEvaluationResult(result, testChecks)
	if err != nil {
		t.Fatalf("FromEvaluationResult returned error: %v", err)
	}

	if report.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", report.Version)
	}

	if report.Schema == "" {
		t.Error("expected schema to be set")
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Tool.Driver.Name != "risk-guard" {
		t.Errorf("expected tool name risk-guard, got %s", run.Tool.Driver.Name)
	}

	if run.Tool.Driver.InformationURI == nil || *run.Tool.Driver.InformationURI != InformationURI {
		t.Errorf("expected information URI %s, got %v", InformationURI, run.Tool.Driver.InformationURI)
	}
}

func TestFromEvaluationResult_ProducesValidJSON(t *testing.T) {
	result := &policy.EvaluationResult{
		Status:   "BLOCKED",
		Source:   "github.com/test/repo",
		Findings: []policy.Finding{},
	}

	report, err := FromEvaluationResult(result, testChecks)
	if err != nil {
		t.Fatalf("FromEvaluationResult returned error: %v", err)
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal SARIF report: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse SARIF JSON: %v", err)
	}

	if parsed["version"] != "2.1.0" {
		t.Errorf("expected version 2.1.0 in JSON, got %v", parsed["version"])
	}

	if parsed["$schema"] == nil {
		t.Error("expected $schema in JSON")
	}
}

func TestFromEvaluationResult_PopulatesRules(t *testing.T) {
	result := &policy.EvaluationResult{
		Status:   "PASS",
		Source:   "github.com/test/repo",
		Findings: []policy.Finding{},
	}

	report, err := FromEvaluationResult(result, testChecks)
	if err != nil {
		t.Fatalf("FromEvaluationResult returned error: %v", err)
	}

	run := report.Runs[0]
	if len(run.Tool.Driver.Rules) == 0 {
		t.Error("expected rules to be populated from check metadata")
	}
}

func TestFromEvaluationResult_ConvertsFindings(t *testing.T) {
	result := &policy.EvaluationResult{
		Status: "BLOCKED",
		Source: "github.com/test/repo",
		Findings: []policy.Finding{
			{
				Kind:           policy.FindingBlocking,
				Package:        "npm:lodash",
				Check:          "VULN_UNFIXED",
				Categories:     []string{"security-vulnerability"},
				Rationale:      "Package has known vulnerabilities",
				Evidence:       []string{"CVE-2021-23337", "CVE-2020-8203"},
				DependencyPath: []string{"root", "dep1", "lodash"},
			},
		},
	}

	report, err := FromEvaluationResult(result, testChecks)
	if err != nil {
		t.Fatalf("FromEvaluationResult returned error: %v", err)
	}

	run := report.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}

	r := run.Results[0]
	if *r.RuleID != "VULN_UNFIXED" {
		t.Errorf("expected ruleId VULN_UNFIXED, got %s", *r.RuleID)
	}

	if r.Level == nil || *r.Level != "error" {
		t.Errorf("expected level error for blocking finding, got %v", r.Level)
	}

	if r.Message.Text == nil || *r.Message.Text == "" {
		t.Error("expected message to be set")
	}

	if len(r.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r.Locations))
	}

	loc := r.Locations[0]
	if len(loc.LogicalLocations) != 1 {
		t.Fatalf("expected 1 logical location, got %d", len(loc.LogicalLocations))
	}

	logLoc := loc.LogicalLocations[0]
	if logLoc.Name == nil || *logLoc.Name != "npm:lodash" {
		t.Errorf("expected logical location name npm:lodash, got %v", logLoc.Name)
	}

	if logLoc.FullyQualifiedName == nil || *logLoc.FullyQualifiedName != "root -> dep1 -> lodash" {
		t.Errorf("expected FQN root -> dep1 -> lodash, got %v", logLoc.FullyQualifiedName)
	}
}

func TestFromEvaluationResult_WithPhysicalLocation(t *testing.T) {
	filename := "package.json"
	lineNum := 42

	result := &policy.EvaluationResult{
		Status: "WARNING",
		Source: "github.com/test/repo",
		Findings: []policy.Finding{
			{
				Kind:           policy.FindingWarning,
				Package:        "npm:axios",
				Check:          "OUTDATED_DEPENDENCY",
				Rationale:      "Dependency is outdated",
				DependencyPath: []string{"root", "axios"},
				RootLocation:   &models.LocationInfo{File: &filename, LineNumber: &lineNum},
			},
		},
	}

	report, err := FromEvaluationResult(result, testChecks)
	if err != nil {
		t.Fatalf("FromEvaluationResult returned error: %v", err)
	}

	r := report.Runs[0].Results[0]
	loc := r.Locations[0]

	if loc.PhysicalLocation == nil {
		t.Fatal("expected physical location to be set")
	}

	if loc.PhysicalLocation.ArtifactLocation == nil ||
		loc.PhysicalLocation.ArtifactLocation.URI == nil ||
		*loc.PhysicalLocation.ArtifactLocation.URI != "package.json" {
		t.Errorf("expected artifact URI package.json, got %v", loc.PhysicalLocation.ArtifactLocation)
	}

	if loc.PhysicalLocation.Region == nil ||
		loc.PhysicalLocation.Region.StartLine == nil ||
		*loc.PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("expected region startLine 42, got %v", loc.PhysicalLocation.Region)
	}
}

func TestNormalizeLogicalName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"local absolute path", "source//home/runner/work/public-test/public-test", "source/public-test"},
		{"local absolute path with commit", "source//home/runner/work/public-test/public-test?commit=abc123", "source/public-test"},
		{"remote source unchanged", "source/github.com/owner/repo", "source/github.com/owner/repo"},
		{"package id unchanged", "package/pypi/pytest?version=9.0.2", "package/pypi/pytest?version=9.0.2"},
		{"plain package name unchanged", "npm:lodash", "npm:lodash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeLogicalName(tt.in); got != tt.want {
				t.Errorf("normalizeLogicalName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestEnsurePhysicalLocations(t *testing.T) {
	run := sarif.NewRunWithInformationURI("risk-guard", InformationURI)

	// (a) result that already has a physical location — must be left untouched.
	withPhys := run.CreateResultForRule("WITH_PHYS")
	withPhys.WithLocations([]*sarif.Location{
		sarif.NewLocation().WithPhysicalLocation(
			sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewSimpleArtifactLocation("package.json")),
		),
	})

	// (b) result with only a logical location.
	logicalOnly := run.CreateResultForRule("LOGICAL_ONLY")
	logicalOnly.WithLocations([]*sarif.Location{
		sarif.NewLocation().WithLogicalLocations([]*sarif.LogicalLocation{{Name: ptr("source/repo"), Kind: ptr("package")}}),
	})

	// (c) result with no locations at all.
	noLoc := run.CreateResultForRule("NO_LOC")

	report, err := sarif.New(sarif.Version210)
	if err != nil {
		t.Fatalf("sarif.New: %v", err)
	}
	report.AddRun(run)

	EnsurePhysicalLocations(report)

	for _, res := range run.Results {
		if !hasPhysicalLocation(res) {
			t.Errorf("rule %s: expected a physical location after EnsurePhysicalLocations", *res.RuleID)
		}
	}

	// (a) preserved its original artifact URI.
	if uri := withPhys.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri == nil || *uri != "package.json" {
		t.Errorf("expected existing physical location to be preserved (package.json), got %v", uri)
	}

	// (b) and (c) anchored at the repo root.
	for _, res := range []*sarif.Result{logicalOnly, noLoc} {
		uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if uri == nil || *uri != RepoRootURI {
			t.Errorf("rule %s: expected anchor URI %q, got %v", *res.RuleID, RepoRootURI, uri)
		}
	}
}

func TestMapFindingKindToLevel(t *testing.T) {
	tests := []struct {
		kind     policy.FindingKind
		expected string
	}{
		{policy.FindingBlocking, "error"},
		{policy.FindingWarning, "warning"},
		{policy.FindingExpired, "error"},
		{policy.FindingAcknowledged, "note"},
		{policy.FindingIgnored, "none"},
		{policy.FindingKind("unknown"), "warning"},
	}

	for _, tt := range tests {
		got := mapFindingKindToLevel(tt.kind)
		if got != tt.expected {
			t.Errorf("mapFindingKindToLevel(%v) = %v, want %v", tt.kind, got, tt.expected)
		}
	}
}

func TestBuildDependencyPathString(t *testing.T) {
	tests := []struct {
		path     []string
		expected string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"root"}, "root"},
		{[]string{"root", "dep1", "dep2"}, "root -> dep1 -> dep2"},
	}

	for _, tt := range tests {
		got := buildDependencyPathString(tt.path)
		if got != tt.expected {
			t.Errorf("buildDependencyPathString(%v) = %v, want %v", tt.path, got, tt.expected)
		}
	}
}

func TestBuildMessage(t *testing.T) {
	tests := []struct {
		name     string
		finding  policy.Finding
		contains []string
	}{
		{
			name: "rationale only",
			finding: policy.Finding{
				Rationale: "Test rationale",
			},
			contains: []string{"Test rationale"},
		},
		{
			name: "with evidence",
			finding: policy.Finding{
				Rationale: "Test rationale",
				Evidence:  []string{"evidence1", "evidence2"},
			},
			contains: []string{"Test rationale", "Evidence:", "- evidence1", "- evidence2"},
		},
		{
			name: "with note",
			finding: policy.Finding{
				Rationale: "Test rationale",
				Note:      "Important note",
			},
			contains: []string{"Test rationale", "Note: Important note"},
		},
		{
			name: "with all fields",
			finding: policy.Finding{
				Rationale: "Test rationale",
				Evidence:  []string{"evidence1"},
				Note:      "Important note",
			},
			contains: []string{"Test rationale", "Evidence:", "- evidence1", "Note: Important note"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMessage(tt.finding)
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("buildMessage() = %q, want it to contain %q", got, want)
				}
			}
		})
	}
}
