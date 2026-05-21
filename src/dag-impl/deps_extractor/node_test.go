package deps_extractor

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func storeUpstream[NodeType any](ctx context.Context, output any) context.Context {
	return context.WithValue(ctx, executiondag.DependsOn[NodeType](), output)
}

func baseCtx() context.Context {
	return ctxutil.SetLogger(context.Background(), zap.NewNop())
}

func sourceInput() dag_impl.Input {
	return dag_impl.Input{
		AnalysisIdentifier: "source/github.com/test/repo",
	}
}

func packageInput() dag_impl.Input {
	return dag_impl.Input{
		AnalysisIdentifier: "package/npm/express",
		Packages: []models.PackageInfo{
			{Ecosystem: "npm", Name: "express"},
		},
	}
}

func TestSourcePath_FreeDepsOnly(t *testing.T) {
	ctx := baseCtx()
	input := sourceInput()

	pdOut := &package_detector.Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		DetectedManifests: []models.ManifestResult{
			{
				DetectedManifest: models.DetectedManifest{Ecosystem: "npm"},
				Dependencies:     []models.Dependency{{AnalysisIdentifier: "package/npm/lodash"}},
			},
			{
				DetectedManifest: models.DetectedManifest{Ecosystem: "npm"},
				Dependencies:     []models.Dependency{{AnalysisIdentifier: "package/npm/chalk"}},
			},
		},
	}
	ctx = storeUpstream[*package_detector.Node](ctx, pdOut)

	node := NewNode()
	out, err := node.Execute(ctx, input)
	require.NoError(t, err)

	require.Equal(t, DepsFromSource, out.DepsSource)
	require.Len(t, out.SourceFreeDeps, 2)
	require.Empty(t, out.SourceLockfileEdges)
	require.Empty(t, out.PackageFreeDeps)
	require.Equal(t, "package/npm/lodash", out.SourceFreeDeps[0].AnalysisIdentifier)
	require.Equal(t, "package/npm/chalk", out.SourceFreeDeps[1].AnalysisIdentifier)
}

func TestSourcePath_LockfileEdgesOnly(t *testing.T) {
	ctx := baseCtx()
	input := sourceInput()

	pdOut := &package_detector.Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		DetectedManifests: []models.ManifestResult{
			{
				DetectedManifest: models.DetectedManifest{Ecosystem: "npm"},
				LockfileDependencies: []models.DepsTreeEdge{
					{ChildKey: "package/npm/express?version=4.18.2", ParentKey: "source/github.com/test/repo"},
					{ChildKey: "package/npm/lodash?version=4.17.21", ParentKey: "package/npm/express?version=4.18.2"},
				},
			},
		},
	}
	ctx = storeUpstream[*package_detector.Node](ctx, pdOut)

	node := NewNode()
	out, err := node.Execute(ctx, input)
	require.NoError(t, err)

	require.Equal(t, DepsFromSource, out.DepsSource)
	require.Empty(t, out.SourceFreeDeps)
	require.Len(t, out.SourceLockfileEdges, 2)
	require.Empty(t, out.PackageFreeDeps)
	require.Equal(t, "package/npm/express?version=4.18.2", out.SourceLockfileEdges[0].ChildKey)
	require.Equal(t, "source/github.com/test/repo", out.SourceLockfileEdges[0].ParentKey)
}

func TestSourcePath_MixedManifests(t *testing.T) {
	ctx := baseCtx()
	input := sourceInput()

	file := "package-lock.json"
	pdOut := &package_detector.Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		DetectedManifests: []models.ManifestResult{
			{
				DetectedManifest: models.DetectedManifest{Ecosystem: "npm"},
				LockfileDependencies: []models.DepsTreeEdge{
					{
						ChildKey:  "package/npm/express?version=4.18.2",
						ParentKey: "source/github.com/test/repo",
						Location:  &models.LocationInfo{File: &file},
					},
				},
			},
			{
				DetectedManifest: models.DetectedManifest{Ecosystem: "pypi"},
				Dependencies:     []models.Dependency{{AnalysisIdentifier: "package/pypi/requests"}},
			},
		},
	}
	ctx = storeUpstream[*package_detector.Node](ctx, pdOut)

	node := NewNode()
	out, err := node.Execute(ctx, input)
	require.NoError(t, err)

	require.Equal(t, DepsFromSource, out.DepsSource)
	require.Len(t, out.SourceFreeDeps, 1)
	require.Len(t, out.SourceLockfileEdges, 1)
	require.Equal(t, "package/pypi/requests", out.SourceFreeDeps[0].AnalysisIdentifier)
	require.Equal(t, "package/npm/express?version=4.18.2", out.SourceLockfileEdges[0].ChildKey)
	require.NotNil(t, out.SourceLockfileEdges[0].Location)
	require.Equal(t, "package-lock.json", *out.SourceLockfileEdges[0].Location.File)
}

func TestSourcePath_PackageFreeDepsFromTransformer(t *testing.T) {
	ctx := baseCtx()
	input := dag_impl.Input{
		AnalysisIdentifier: "source/github.com/test/repo",
		Packages: []models.PackageInfo{
			{Ecosystem: "npm", Name: "my-pkg"},
		},
	}

	pdOut := &package_detector.Output{
		BaseOutput:        dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		DetectedManifests: []models.ManifestResult{},
	}
	ctx = storeUpstream[*package_detector.Node](ctx, pdOut)

	tOut := &transformer.Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		Outputs: []transformer.PackageOutput{
			{
				Ecosystem: "npm",
				Name:      "my-pkg",
				Metadata: &models.PackageMetadata{
					Dependencies: []models.Dependency{
						{AnalysisIdentifier: "package/npm/dep-a"},
						{AnalysisIdentifier: "package/npm/dep-b"},
					},
				},
			},
		},
	}
	ctx = storeUpstream[*transformer.Node](ctx, tOut)

	node := NewNode()
	out, err := node.Execute(ctx, input)
	require.NoError(t, err)

	require.Equal(t, DepsFromSource, out.DepsSource)
	require.Empty(t, out.SourceFreeDeps)
	require.Len(t, out.PackageFreeDeps, 2)
	require.Equal(t, "package/npm/dep-a", out.PackageFreeDeps[0].AnalysisIdentifier)
}

func TestPackagePath_ViaTransformer(t *testing.T) {
	ctx := baseCtx()
	input := packageInput()

	tOut := &transformer.Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		Outputs: []transformer.PackageOutput{
			{
				Ecosystem: "npm",
				Name:      "express",
				Metadata: &models.PackageMetadata{
					Dependencies: []models.Dependency{
						{AnalysisIdentifier: "package/npm/body-parser"},
						{AnalysisIdentifier: "package/npm/cookie"},
					},
				},
			},
		},
	}
	ctx = storeUpstream[*transformer.Node](ctx, tOut)

	node := NewNode()
	out, err := node.Execute(ctx, input)
	require.NoError(t, err)

	require.Equal(t, DepsFromPackage, out.DepsSource)
	require.Empty(t, out.SourceFreeDeps)
	require.Empty(t, out.SourceLockfileEdges)
	require.Len(t, out.PackageFreeDeps, 2)
	require.Equal(t, "package/npm/body-parser", out.PackageFreeDeps[0].AnalysisIdentifier)
}

func TestBothUpstreamsSkipped(t *testing.T) {
	ctx := baseCtx()
	input := sourceInput()

	node := NewNode()
	out, err := node.Execute(ctx, input)
	require.NoError(t, err)

	require.Equal(t, DepsFromSource, out.DepsSource)
	require.Empty(t, out.SourceFreeDeps)
	require.Empty(t, out.SourceLockfileEdges)
	require.Empty(t, out.PackageFreeDeps)
	require.Equal(t, executiondag.StatusSuccess, out.GetStatus())
}

func TestPersistKey(t *testing.T) {
	out := NewOutput(executiondag.StatusSuccess, "", dag_impl.Input{})
	require.Equal(t, "dependencies", out.PersistKey())
}

func TestNodeMeta(t *testing.T) {
	node := NewNode()
	require.Equal(t, "transform", node.Kind())
	require.False(t, node.AllowAutoSkip())

	deps := node.GetDependencies()
	require.Len(t, deps, 2)
	require.Equal(t, executiondag.DependsOn[*package_detector.Node](), deps[0])
	require.Equal(t, executiondag.DependsOn[*transformer.Node](), deps[1])
}

func TestPackagePath_MissingMetadataSkipped(t *testing.T) {
	ctx := baseCtx()
	input := dag_impl.Input{
		AnalysisIdentifier: "package/npm/express",
		Packages: []models.PackageInfo{
			{Ecosystem: "npm", Name: "express"},
			{Ecosystem: "npm", Name: "nonexistent"},
		},
	}

	tOut := &transformer.Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		Outputs: []transformer.PackageOutput{
			{
				Ecosystem: "npm",
				Name:      "express",
				Metadata: &models.PackageMetadata{
					Dependencies: []models.Dependency{
						{AnalysisIdentifier: "package/npm/body-parser"},
					},
				},
			},
		},
	}
	ctx = storeUpstream[*transformer.Node](ctx, tOut)

	node := NewNode()
	out, err := node.Execute(ctx, input)
	require.NoError(t, err)

	require.Equal(t, DepsFromPackage, out.DepsSource)
	require.Len(t, out.PackageFreeDeps, 1)
	require.Equal(t, "package/npm/body-parser", out.PackageFreeDeps[0].AnalysisIdentifier)
}

func TestCreateSkippedOutput(t *testing.T) {
	node := NewNode()
	input := sourceInput()
	out := node.CreateSkippedOutput("test reason", input)

	require.Equal(t, executiondag.StatusSkipped, out.GetStatus())
	require.Equal(t, "test reason", out.GetStatusReason())
}
