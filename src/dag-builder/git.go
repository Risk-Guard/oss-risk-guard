package dag_builder

import (
	"context"
	"risk-guard/src/common"
	"risk-guard/src/dag-impl/git_clone_content"
	"risk-guard/src/dag-impl/git_clone_metadata"
	"risk-guard/src/dag-impl/git_resolve"
	"risk-guard/src/dag-impl/license_files"
	"risk-guard/src/dag-impl/org_security_policy"
	"risk-guard/src/dag-impl/package_detector"
	"risk-guard/src/dag-impl/policy_loader"
	"risk-guard/src/dag-impl/unsupported_manifests"
	"risk-guard/src/ecosystem/def"
	"risk-guard/src/language/dag/transformer"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
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

	executiondag.AddNode(dag, org_security_policy.NewNode())

	executiondag.AddNode(dag, package_detector.NewNode(ecosystems))

	executiondag.AddNode(dag, license_files.NewNode())

	executiondag.AddNode(dag, policy_loader.NewNode())

	executiondag.AddNode(dag, unsupported_manifests.NewNode())

	return nil
}
