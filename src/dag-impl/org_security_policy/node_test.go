package org_security_policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func testCtx() context.Context {
	return ctxutil.SetLogger(context.Background(), zap.NewNop())
}

func TestNode_Execute_FoundOnMain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/myorg/.github/main/SECURITY.md" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	orig := rawGitHubBaseURL
	rawGitHubBaseURL = server.URL
	defer func() { rawGitHubBaseURL = orig }()

	sourceURL := "https://github.com/myorg/myrepo"
	input := dag_impl.Input{SourceURL: &sourceURL}
	node := NewNode()

	output, err := node.Execute(testCtx(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !output.Found {
		t.Error("expected Found=true")
	}
	if output.PolicyPath != "myorg/.github/SECURITY.md" {
		t.Errorf("expected policy path 'myorg/.github/SECURITY.md', got %q", output.PolicyPath)
	}
}

func TestNode_Execute_FoundOnMasterFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/myorg/.github/master/SECURITY.md" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	orig := rawGitHubBaseURL
	rawGitHubBaseURL = server.URL
	defer func() { rawGitHubBaseURL = orig }()

	sourceURL := "https://github.com/myorg/myrepo"
	input := dag_impl.Input{SourceURL: &sourceURL}
	node := NewNode()

	output, err := node.Execute(testCtx(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !output.Found {
		t.Error("expected Found=true")
	}
	if output.PolicyPath != "myorg/.github/SECURITY.md" {
		t.Errorf("expected policy path 'myorg/.github/SECURITY.md', got %q", output.PolicyPath)
	}
}

func TestNode_Execute_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	orig := rawGitHubBaseURL
	rawGitHubBaseURL = server.URL
	defer func() { rawGitHubBaseURL = orig }()

	sourceURL := "https://github.com/myorg/myrepo"
	input := dag_impl.Input{SourceURL: &sourceURL}
	node := NewNode()

	output, err := node.Execute(testCtx(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Found {
		t.Error("expected Found=false")
	}
	if output.PolicyPath != "" {
		t.Errorf("expected empty policy path, got %q", output.PolicyPath)
	}
}

func TestNode_Execute_NonGitHubURL(t *testing.T) {
	sourceURL := "https://gitlab.com/myorg/myrepo"
	input := dag_impl.Input{SourceURL: &sourceURL}
	node := NewNode()

	output, err := node.Execute(testCtx(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Found {
		t.Error("expected Found=false for non-GitHub URL")
	}
	if output.Status != executiondag.StatusSuccess {
		t.Errorf("expected StatusSkipped, got %v", output.Status)
	}
}

func TestNode_Execute_NoSourceURL(t *testing.T) {
	input := dag_impl.Input{}
	node := NewNode()

	output, err := node.Execute(testCtx(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Found {
		t.Error("expected Found=false when no source URL")
	}
	if output.Status != executiondag.StatusSuccess {
		t.Errorf("expected StatusSkipped, got %v", output.Status)
	}
}

func TestNode_Execute_NetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()

	orig := rawGitHubBaseURL
	rawGitHubBaseURL = server.URL
	defer func() { rawGitHubBaseURL = orig }()

	sourceURL := "https://github.com/myorg/myrepo"
	input := dag_impl.Input{SourceURL: &sourceURL}
	node := NewNode()

	output, err := node.Execute(testCtx(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Found {
		t.Error("expected Found=false on network error")
	}
	if output.Status != executiondag.StatusSuccess {
		t.Errorf("expected StatusSuccess (best-effort), got %v", output.Status)
	}
}

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(deps))
	}

	expectedDep := executiondag.DependsOn[*git_resolve.Node]()
	if deps[0] != expectedDep {
		t.Error("node should depend on *git_resolve.Node")
	}
}

func TestNode_Kind(t *testing.T) {
	node := NewNode()
	if kind := node.Kind(); kind != "fetch" {
		t.Errorf("expected kind 'fetch', got %q", kind)
	}
}

func TestNode_PersistKey(t *testing.T) {
	sourceURL := "https://github.com/test/repo"
	input := dag_impl.Input{SourceURL: &sourceURL}
	output := NewOutput(executiondag.StatusSuccess, "test", false, "", input)
	if key := output.PersistKey(); key != "org-security-policy" {
		t.Errorf("expected persist key 'org-security-policy', got %q", key)
	}
}
