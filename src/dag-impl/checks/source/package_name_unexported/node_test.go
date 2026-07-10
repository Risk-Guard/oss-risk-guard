package package_name_unexported

import (
	"context"
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector_published"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func makeTestCtx(t *testing.T, manifests []models.ManifestResult) context.Context {
	t.Helper()
	return makeTestCtxRef(t, manifests, package_detector_published.SourceRefHead, "")
}

func makeTestCtxRef(t *testing.T, manifests []models.ManifestResult, sourceRef, sourceCommit string) context.Context {
	t.Helper()
	log, err := logger.NewLogger("error")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	ctx := ctxutil.SetLogger(context.Background(), log)

	detectorOut := &package_detector_published.Output{
		BaseOutput:        dag_impl.NewBaseOutput(executiondag.StatusSuccess, "test", dag_impl.Input{}),
		DetectedManifests: manifests,
		SourceRef:         sourceRef,
		SourceCommit:      sourceCommit,
	}
	ctx = context.WithValue(ctx, executiondag.DependsOn[*package_detector_published.Node](), detectorOut)

	return ctx
}

func evidenceContains(evidence []string, substr string) bool {
	for _, e := range evidence {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

func TestExecute_Violation_DisclosesSourceRef(t *testing.T) {
	manifests := []models.ManifestResult{{
		DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"pyproject.toml"}},
		Name:             nil,
	}}
	input := dag_impl.Input{Packages: []models.PackageInfo{{Ecosystem: "pypi", Name: "PyYAML", Version: "6.0"}}}

	ctxHead := makeTestCtx(t, manifests)
	outHead, err := NewNode().Execute(ctxHead, input)
	if err != nil {
		t.Fatalf("Execute (HEAD) returned error: %v", err)
	}
	if !evidenceContains(outHead.Check.Evidence, "Scanned repository HEAD — no gitHead recorded for pypi/PyYAML@6.0") {
		t.Errorf("HEAD evidence %q missing provenance disclosure", outHead.Check.Evidence)
	}

	ctxGH := makeTestCtxRef(t, manifests, package_detector_published.SourceRefGitHead, "deadbeef1234567890abcdef1234567890abcdef")
	outGH, err := NewNode().Execute(ctxGH, input)
	if err != nil {
		t.Fatalf("Execute (gitHead) returned error: %v", err)
	}
	if !evidenceContains(outGH.Check.Evidence, "Scanned source as published (gitHead deadbee)") {
		t.Errorf("gitHead evidence %q missing provenance disclosure", outGH.Check.Evidence)
	}
}

func TestExecute_NilNameManifest_ShouldViolate(t *testing.T) {
	manifests := []models.ManifestResult{
		{
			DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"pyproject.toml", "setup.py"}},
			Name:             nil,
		},
	}

	ctx := makeTestCtx(t, manifests)
	node := NewNode()
	input := dag_impl.Input{
		Packages: []models.PackageInfo{
			{Ecosystem: "pypi", Name: "PyYAML"},
		},
	}

	output, err := node.Execute(ctx, input)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if output.Check.CheckStatus != storage.StatusViolation {
		t.Errorf("Expected violation when manifest has nil Name (parse failure), got %s: %s",
			output.Check.CheckStatus, output.Check.Rationale)
	}
}

func TestExecute_WithExportedName_ShouldComply(t *testing.T) {
	name := "PyYAML"
	manifests := []models.ManifestResult{
		{
			DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"pyproject.toml"}},
			Name:             &name,
		},
	}

	ctx := makeTestCtx(t, manifests)
	node := NewNode()
	input := dag_impl.Input{
		Packages: []models.PackageInfo{
			{Ecosystem: "pypi", Name: "PyYAML"},
		},
	}

	output, err := node.Execute(ctx, input)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if output.Check.CheckStatus != storage.StatusCompliant {
		t.Errorf("Expected compliant when manifest has exported name, got %s: %s",
			output.Check.CheckStatus, output.Check.Rationale)
	}
}
