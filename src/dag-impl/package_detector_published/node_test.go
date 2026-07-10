package package_detector_published

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_published_content"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func testLogCtx(t *testing.T) context.Context {
	t.Helper()
	log, err := logger.NewLogger("error")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return ctxutil.SetLogger(context.Background(), log)
}

// TestExecute_HEADFallback_SetsSourceRefHead: no published (gitHead) tree → the
// node mirrors HEAD detection and records SourceRefHead.
func TestExecute_HEADFallback_SetsSourceRefHead(t *testing.T) {
	input := dag_impl.Input{}
	manifests := []models.ManifestResult{{
		DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
	}}

	ctx := testLogCtx(t)
	publishedOut := git_clone_published_content.NewOutput(executiondag.StatusSkipped, "no gitHead", "", "", input)
	ctx = context.WithValue(ctx, executiondag.DependsOn[*git_clone_published_content.Node](), publishedOut)
	headOut := package_detector.NewOutput(executiondag.StatusSuccess, "detected", manifests, input)
	ctx = context.WithValue(ctx, executiondag.DependsOn[*package_detector.Node](), headOut)

	out, err := NewNode(nil).Execute(ctx, input)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if out.SourceRef != SourceRefHead {
		t.Errorf("SourceRef = %q, want %q", out.SourceRef, SourceRefHead)
	}
	if out.SourceCommit != "" {
		t.Errorf("SourceCommit = %q, want empty on HEAD fallback", out.SourceCommit)
	}
	if len(out.DetectedManifests) != 1 {
		t.Errorf("expected HEAD manifests mirrored, got %d", len(out.DetectedManifests))
	}
}

// TestExecute_GitHead_SetsSourceRefGitHead: a successful published clone → the
// node scans that tree and records SourceRefGitHead with the commit. An empty
// tree yields zero manifests, which is fine for asserting the ref plumbing.
func TestExecute_GitHead_SetsSourceRefGitHead(t *testing.T) {
	input := dag_impl.Input{AnalysisIdentifier: "source/npm/foo"}
	const commit = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"

	ctx := testLogCtx(t)
	publishedOut := git_clone_published_content.NewOutput(executiondag.StatusSuccess, "cloned", t.TempDir(), commit, input)
	ctx = context.WithValue(ctx, executiondag.DependsOn[*git_clone_published_content.Node](), publishedOut)
	headOut := package_detector.NewOutput(executiondag.StatusSuccess, "detected", nil, input)
	ctx = context.WithValue(ctx, executiondag.DependsOn[*package_detector.Node](), headOut)

	out, err := NewNode(nil).Execute(ctx, input)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if out.SourceRef != SourceRefGitHead {
		t.Errorf("SourceRef = %q, want %q", out.SourceRef, SourceRefGitHead)
	}
	if out.SourceCommit != commit {
		t.Errorf("SourceCommit = %q, want %q", out.SourceCommit, commit)
	}
}
