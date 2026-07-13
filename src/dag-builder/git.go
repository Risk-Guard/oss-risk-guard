package dag_builder

import (
	"context"
	"fmt"

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
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/provenance_verify"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/unsupported_manifests"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/provenance"

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

	// Build-provenance (Sigstore) verification. Constructed once; verifies npm
	// attestations against the declared repo. Its result feeds the published-clone
	// commit choice and the provenance/name/source-url/artifact checks.
	provVerifier, err := provenance.NewSigstoreVerifier()
	if err != nil {
		return fmt.Errorf("initializing provenance verifier: %w", err)
	}
	executiondag.AddNode(dag, provenance_verify.NewNode(provVerifier))

	// Clone of the source tree at the analyzed version's published commit, chosen in
	// order of assurance: verified provenance, then the version's gitHead, then a
	// release tag. Needs git_resolve (normalized URL / privacy), transformer (the
	// gitHead), and provenance_verify (the strongest pin). No-op when none available.
	publishedCloneDeps := []any{
		executiondag.DependsOn[*git_resolve.Node](),
		executiondag.DependsOn[*transformer.Node](),
		executiondag.DependsOn[*provenance_verify.Node](),
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
