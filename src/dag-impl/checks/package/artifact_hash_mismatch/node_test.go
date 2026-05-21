package artifact_hash_mismatch

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/api/routes"
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/artifact_fetch"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"github.com/stretchr/testify/require"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	require.Len(t, deps, 1)
	require.Equal(t, executiondag.DependsOn[*artifact_fetch.Node](), deps[0])
}

func TestNode_GetCode(t *testing.T) {
	node := NewNode()
	require.Equal(t, "ARTIFACT_HASH_MISMATCH", node.GetCode())
}

func TestNode_GetCategories(t *testing.T) {
	node := NewNode()
	categories := node.GetCategories()

	require.Len(t, categories, 1)
	require.Contains(t, categories, category.RiskCategoryCritical)
}

func TestCheck_NoViolation_AllVerified(t *testing.T) {
	extractions := []routes.ArtifactExtraction{
		{
			Ecosystem:   "npm",
			PackageName: "express",
			Verified:    true,
			VerifyError: nil,
		},
		{
			Ecosystem:   "npm",
			PackageName: "lodash",
			Verified:    true,
			VerifyError: nil,
		},
	}

	node := NewNode()
	output := node.evaluate(extractions, dag_impl.Input{})

	require.Equal(t, storage.StatusCompliant, output.Check.CheckStatus)
}

func TestCheck_Violation_HashMismatch(t *testing.T) {
	errStr := "hash mismatch: expected abc, got def"
	extractions := []routes.ArtifactExtraction{
		{
			Ecosystem:   "npm",
			PackageName: "express",
			Verified:    true,
			VerifyError: nil,
		},
		{
			Ecosystem:   "npm",
			PackageName: "malicious-pkg",
			ArtifactURL: "https://registry.npmjs.org/malicious-pkg/-/malicious-pkg-1.0.0.tgz",
			Verified:    false,
			VerifyError: &errStr,
		},
	}

	node := NewNode()
	output := node.evaluate(extractions, dag_impl.Input{})

	require.Equal(t, storage.StatusViolation, output.Check.CheckStatus)
	require.Len(t, output.Check.Evidence, 1)
	require.Contains(t, output.Check.Evidence[0], "npm/malicious-pkg")
	require.Contains(t, output.Check.Evidence[0], "hash mismatch")
}

func TestCheck_Skipped_NoExtractions(t *testing.T) {
	node := NewNode()
	output := node.evaluate(nil, dag_impl.Input{})

	require.Equal(t, storage.StatusCompliant, output.Check.CheckStatus)
}

func TestCheck_SkipsSkippedExtractions(t *testing.T) {
	skipReason := "no distribution URL"
	extractions := []routes.ArtifactExtraction{
		{
			Ecosystem:   "npm",
			PackageName: "express",
			SkipReason:  &skipReason,
		},
	}

	node := NewNode()
	output := node.evaluate(extractions, dag_impl.Input{})

	require.Equal(t, storage.StatusCompliant, output.Check.CheckStatus)
}
