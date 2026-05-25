package git_clone_content

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func setupTestContext(t *testing.T, outputDir string) context.Context {
	t.Helper()
	log, err := logger.NewLogger("error")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	ctx := context.Background()
	ctx = ctxutil.SetLogger(ctx, log)

	cfg := &environment.Config{}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = runpath.SetCacheDir(ctx, t.TempDir())

	return ctx
}

func TestNode_Execute_NoSourceURL(t *testing.T) {
	node := NewNode(false, nil, nil)
	input := &dag_impl.Input{
		SourceURL: nil,
		Packages:  nil,
	}

	ctx := setupTestContext(t, "/tmp/test-output")

	output, err := node.Execute(ctx, *input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if output.GetStatus() != executiondag.StatusSkipped {
		t.Errorf("Expected StatusSkipped, got %v", output.GetStatus())
	}

	if output.GetStatusReason() != "no source URL provided" {
		t.Errorf("Expected reason 'no source URL provided', got '%s'", output.GetStatusReason())
	}

	if output.RepoPath != "" {
		t.Errorf("Expected empty repo path, got '%s'", output.RepoPath)
	}
}

func TestNode_Execute_EmptySourceURL(t *testing.T) {
	node := NewNode(false, nil, nil)
	emptyURL := ""
	input := &dag_impl.Input{
		SourceURL: &emptyURL,
		Packages:  nil,
	}

	ctx := setupTestContext(t, "/tmp/test-output")

	output, err := node.Execute(ctx, *input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if output.GetStatus() != executiondag.StatusSkipped {
		t.Errorf("Expected StatusSkipped, got %v", output.GetStatus())
	}

	if output.GetStatusReason() != "no source URL provided" {
		t.Errorf("Expected reason 'no source URL provided', got '%s'", output.GetStatusReason())
	}
}

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode(false, nil, nil)
	deps := node.GetDependencies()

	if len(deps) != 0 {
		t.Errorf("Expected no dependencies, got %d", len(deps))
	}
}

func TestOutput_RepoPath(t *testing.T) {
	url := "https://github.com/test/repo"
	output := NewOutput(executiondag.StatusSuccess, "", "/path/to/repo", "abc123", dag_impl.Input{SourceURL: &url})

	path := output.RepoPath
	if path != "/path/to/repo" {
		t.Errorf("Expected path '/path/to/repo', got '%s'", path)
	}
}

func TestOutput_GetOutput(t *testing.T) {
	url := "https://github.com/test/repo"
	output := NewOutput(executiondag.StatusSuccess, "", "/path/to/repo", "abc123", dag_impl.Input{SourceURL: &url})

	outputData := output.GetOutput()
	if outputData == nil {
		t.Fatal("Expected non-nil output")
		return
	}
	if outputData.SourceURL == nil {
		t.Fatal("Expected non-nil source URL in output")
		return
	}
	if *outputData.SourceURL != url {
		t.Errorf("Expected URL '%s', got '%s'", url, *outputData.SourceURL)
	}
	if len(outputData.Packages) != 0 {
		t.Errorf("Expected empty packages slice, got %d packages", len(outputData.Packages))
	}
}

func TestOutput_StatusSuccess(t *testing.T) {
	url := "https://github.com/test/repo"
	output := NewOutput(executiondag.StatusSuccess, "", "/path/to/repo", "abc123", dag_impl.Input{SourceURL: &url})

	if output.GetStatus() != executiondag.StatusSuccess {
		t.Errorf("Expected StatusSuccess, got %v", output.GetStatus())
	}
	if output.GetStatusReason() != "" {
		t.Errorf("Expected empty reason, got '%s'", output.GetStatusReason())
	}
}

func TestOutput_StatusSkipped(t *testing.T) {
	url := "https://github.com/test/repo"
	output := NewOutput(executiondag.StatusSkipped, "test skip reason", "", "", dag_impl.Input{SourceURL: &url})

	if output.GetStatus() != executiondag.StatusSkipped {
		t.Errorf("Expected StatusSkipped, got %v", output.GetStatus())
	}
	if output.GetStatusReason() != "test skip reason" {
		t.Errorf("Expected reason 'test skip reason', got '%s'", output.GetStatusReason())
	}
}

func TestOutput_PersistKey(t *testing.T) {
	url := "https://github.com/test/repo"
	output := NewOutput(executiondag.StatusSuccess, "", "/path/to/repo", "abc123", dag_impl.Input{SourceURL: &url})
	if output.PersistKey() != "clone_content" {
		t.Errorf("Expected PersistKey 'clone_content', got '%s'", output.PersistKey())
	}
}
