package version_transformer

import (
	"risk-guard/src/language/dag/fetcher"
	"risk-guard/src/models"
	"testing"

	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode(nil)
	deps := node.GetDependencies()

	if len(deps) != 1 {
		t.Fatalf("Expected 1 dependency, got %d", len(deps))
	}

	// Verify it depends on FetcherOutput
	expectedDep := executiondag.DependsOn[*fetcher.Node]()
	if deps[0] != expectedDep {
		t.Error("Node should depend on *fetcher.Output")
	}
}

func TestNode_CreateSkippedOutput(t *testing.T) {
	node := NewNode(nil)
	output := node.CreateSkippedOutput("test reason", dag_impl.Input{})

	if output.GetStatus() != executiondag.StatusSkipped {
		t.Errorf("expected status skipped, got %v", output.GetStatus())
	}
	if output.GetStatusReason() != "test reason" {
		t.Errorf("expected reason 'test reason', got %q", output.GetStatusReason())
	}
}

func TestOutput_GetVersionMetadata(t *testing.T) {
	// Test GetVersionMetadata helper method
	outputs := []VersionOutput{
		{
			Ecosystem: "npm",
			Name:      "express",
			Metadata: &models.VersionMetadata{
				Ecosystem:   "npm",
				PackageName: "express",
			},
		},
	}
	output := NewOutput(executiondag.StatusSuccess, "", outputs, dag_impl.Input{})

	result := output.GetVersionMetadata("npm", "express")
	if result == nil {
		t.Fatal("Expected non-nil version metadata")
		return
	}
	if result.PackageName != "express" {
		t.Errorf("Expected package name 'express', got %s", result.PackageName)
	}

	// Test non-existent package
	result = output.GetVersionMetadata("npm", "nonexistent")
	if result != nil {
		t.Error("Expected nil for non-existent package")
	}
}

// Note: Integration tests for actual transformation (Execute method) should be in a separate file
// with build tag "integration" and run the full DAG with real fetcher+transformer nodes
