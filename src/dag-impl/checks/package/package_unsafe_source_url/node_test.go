package package_unsafe_source_url

import (
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"testing"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 1 {
		t.Errorf("Expected 1 dependency, got %d", len(deps))
	}
}

func TestNode_CreateSkippedOutput(t *testing.T) {
	node := NewNode()
	input := dag_impl.Input{}
	output := node.CreateSkippedOutput("test reason", input)

	if output.Check.CheckStatus != storage.StatusSkipped {
		t.Errorf("Expected check status %s, got %s", storage.StatusSkipped, output.Check.CheckStatus)
	}
	if output.Check.CheckCode != CheckCode {
		t.Errorf("Expected check code %s, got %s", CheckCode, output.Check.CheckCode)
	}
	if output.Check.Rationale != "test reason" {
		t.Errorf("Expected rationale 'test reason', got %s", output.Check.Rationale)
	}
}

func TestNode_Kind(t *testing.T) {
	node := NewNode()
	if node.Kind() != "check" {
		t.Errorf("Expected kind 'check', got %s", node.Kind())
	}
}

func TestCheckCodeConstant(t *testing.T) {
	if CheckCode != "PACKAGE_UNSAFE_SOURCE_URL" {
		t.Errorf("CheckCode constant has unexpected value: %s", CheckCode)
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode()
	if node == nil {
		t.Fatal("NewNode() should not return nil")
		return
	}
	if node.Code != CheckCode {
		t.Errorf("Expected node.Code to be %s, got %s", CheckCode, node.Code)
	}
}

// Note: Full Execute() tests require DAG context setup and are covered by integration tests
