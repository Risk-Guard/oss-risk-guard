package package_detector

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"github.com/stretchr/testify/require"
)

func ptr(s string) *string { return &s }

func TestNewOutput_SourceAnalysis_SetsPackagesOnOutput(t *testing.T) {
	input := dag_impl.Input{
		AnalysisIdentifier: "source/github.com/test/repo",
	}
	manifests := []models.ManifestResult{
		{
			DetectedManifest: models.DetectedManifest{Ecosystem: "npm"},
			Name:             ptr("express"),
		},
	}

	out := NewOutput(executiondag.StatusSuccess, "detected 1 package(s)", manifests, input)

	require.NotNil(t, out.Output)
	require.Len(t, out.Output.Packages, 1)
	require.Equal(t, "npm", out.Output.Packages[0].Ecosystem)
	require.Equal(t, "express", out.Output.Packages[0].Name)
}

func TestNewOutput_PackageAnalysis_DoesNotSetOutput(t *testing.T) {
	input := dag_impl.Input{
		AnalysisIdentifier: "package/npm/core-js-compat",
		Packages: []models.PackageInfo{
			{Ecosystem: "npm", Name: "core-js-compat", Version: "3.47.0"},
		},
	}
	manifests := []models.ManifestResult{
		{
			DetectedManifest: models.DetectedManifest{Ecosystem: "npm"},
			Name:             ptr("core-js-compat"),
		},
	}

	out := NewOutput(executiondag.StatusSuccess, "detected 1 package(s)", manifests, input)

	require.Nil(t, out.Output)
	require.Len(t, out.DetectedManifests, 1)
}

func TestNewOutput_EmptyManifests_DoesNotSetOutput(t *testing.T) {
	input := dag_impl.Input{
		AnalysisIdentifier: "source/github.com/test/repo",
	}

	out := NewOutput(executiondag.StatusSuccess, "detected 0 package(s)", nil, input)

	require.Nil(t, out.Output)
}
