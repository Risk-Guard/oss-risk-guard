package package_name_unexported

import (
	"context"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/package_detector"
	"risk-guard/src/lib/common/storage"
	"risk-guard/src/logger"
	"risk-guard/src/models"
	"testing"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
)

func makeTestCtx(t *testing.T, manifests []models.ManifestResult) context.Context {
	t.Helper()
	log, err := logger.NewLogger("error")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	ctx := ctxutil.SetLogger(context.Background(), log)

	detectorOut := &package_detector.Output{
		BaseOutput:        dag_impl.NewBaseOutput(executiondag.StatusSuccess, "test", dag_impl.Input{}),
		DetectedManifests: manifests,
	}
	ctx = context.WithValue(ctx, executiondag.DependsOn[*package_detector.Node](), detectorOut)

	return ctx
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
