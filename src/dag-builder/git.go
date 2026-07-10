package dag_builder

import (
	"context"

	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_content"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_published_content"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/license_files"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/org_security_policy"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector_published"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/policy_loader"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/unsupported_manifests"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func BuildGitDag(dag *executiondag.DAG[dag_impl.Input], input dag_impl.Input, ctx context.Context) error {
	var isLocal bool
	var err error
	if input.HasSourceURL() {
		isLocal, err = common.IsLocalPath(*input.SourceURL)
		if err != nil {
			return err
		}
	} else {
		isLocal = false
	}

	ecosystems := def.All()

	var gitResolveDeps []any
	if !input.HasSourceURL() && len(input.Packages) > 0 {
		gitResolveDeps = []any{executiondag.DependsOn[*transformer.Node]()}
	}

	executiondag.AddNode(dag, git_resolve.NewNode(isLocal, gitResolveDeps))

	gitCloneDeps := []any{executiondag.DependsOn[*git_resolve.Node]()}
	executiondag.AddNode(dag, git_clone_content.NewNode(isLocal, gitCloneDeps, ecosystems))

	gitCloneMetadataDeps := []any{executiondag.DependsOn[*git_resolve.Node]()}
	executiondag.AddNode(dag, git_clone_metadata.NewNode(isLocal, gitCloneMetadataDeps))

	// Clone of the source tree at the analyzed version's published gitHead. Needs
	// git_resolve (for the normalized URL / privacy) and transformer (for the
	// version's gitHead). No-op when no gitHead is available.
	publishedCloneDeps := []any{
		executiondag.DependsOn[*git_resolve.Node](),
		executiondag.DependsOn[*transformer.Node](),
	}
	executiondag.AddNode(dag, git_clone_published_content.NewNode(isLocal, publishedCloneDeps, ecosystems))

	executiondag.AddNode(dag, org_security_policy.NewNode())

	executiondag.AddNode(dag, package_detector.NewNode(ecosystems))

	// Package detection over the published (gitHead) tree, falling back to HEAD
	// detection. Provenance checks (PACKAGE_NAME_MISMATCH) consume this instead of
	// package_detector so they compare against the source as-published.
	executiondag.AddNode(dag, package_detector_published.NewNode(ecosystems))

	executiondag.AddNode(dag, license_files.NewNode())

	executiondag.AddNode(dag, policy_loader.NewNode())

	executiondag.AddNode(dag, unsupported_manifests.NewNode())

	return nil
}
