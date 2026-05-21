package dag_builder

import (
	"context"
	artifactfetcher "github.com/Risk-Guard/oss-risk-guard/src/artifact/fetcher"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/artifact_fetch"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/deps_extractor"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/fetcher"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/version_transformer"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// BuildDag adds language-specific package registry nodes to the DAG.
// This includes:
// - fetcher: Fetches raw package data from language registries
// - transformer: Transforms raw data into standardized package metadata
// - version_transformer: Transforms raw data into version history metadata
//
// Parameters:
// - dag: The DAG to add nodes to
// - input: The input containing source URL and packages
// - languages: Map of ecosystem name to Language implementation
//
// Behavior:
// - If input has SourceURL: fetcher depends on package_detector
// - If input has packages but no SourceURL: fetcher has no git dependency
// - Both transformer and version_transformer depend on fetcher (run in parallel)
func BuildDag(dag *executiondag.DAG[dag_impl.Input], input *dag_impl.Input, languages map[string]language.Language, artifactFetcher artifactfetcher.Fetcher, ctx context.Context) {
	// Determine if fetcher should depend on package_detector
	// This happens when we have a source URL (forward flow)
	var fetcherDeps []any
	if input.SourceURL != nil {
		fetcherDeps = []any{executiondag.DependsOn[*package_detector.Node]()}
	}

	// Add fetcher node with optional package_detector dependency
	executiondag.AddNode(dag, fetcher.NewNode(languages, fetcherDeps))

	// Add transformer node (depends on fetcher)
	executiondag.AddNode(dag, transformer.NewNode(languages))

	// Add version transformer node (also depends on fetcher, runs in parallel with transformer)
	executiondag.AddNode(dag, version_transformer.NewNode(languages))

	// Add artifact fetch node (depends on transformer for distribution URLs)
	executiondag.AddNode(dag, artifact_fetch.NewNode(languages, artifactFetcher))

	executiondag.AddNode(dag, deps_extractor.NewNode())
}
