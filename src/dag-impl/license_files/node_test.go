package license_files

import (
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_content"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"testing"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 1 {
		t.Fatalf("Expected 1 dependency, got %d", len(deps))
	}

	expectedDep := executiondag.DependsOn[*git_clone_content.Node]()
	if deps[0] != expectedDep {
		t.Error("Node should depend on *git_clone_content.Node")
	}
}

func TestNode_CreateSkippedOutput(t *testing.T) {
	node := NewNode()
	output := node.CreateSkippedOutput("test reason", dag_impl.Input{})

	if output.GetStatus() != executiondag.StatusSkipped {
		t.Errorf("expected status skipped, got %v", output.GetStatus())
	}
	if output.GetStatusReason() != "test reason" {
		t.Errorf("expected reason 'test reason', got %q", output.GetStatusReason())
	}
	if len(output.Files) != 0 {
		t.Errorf("expected empty files, got %d", len(output.Files))
	}
}

func TestOutput_NewOutput(t *testing.T) {
	files := []models.LicenseFile{
		{Path: "LICENSE"},
	}

	output := NewOutput(executiondag.StatusSuccess, "", files, dag_impl.Input{})

	if output.GetStatus() != executiondag.StatusSuccess {
		t.Errorf("expected status success, got %v", output.GetStatus())
	}
	if len(output.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(output.Files))
	}
	if output.Files[0].Path != "LICENSE" {
		t.Errorf("expected file path 'LICENSE', got %s", output.Files[0].Path)
	}
}

func TestOutput_EmptyFiles(t *testing.T) {
	output := NewOutput(executiondag.StatusSkipped, "no licenses found", []models.LicenseFile{}, dag_impl.Input{})

	if output.GetStatus() != executiondag.StatusSkipped {
		t.Errorf("expected status skipped, got %v", output.GetStatus())
	}
	if len(output.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(output.Files))
	}
}
