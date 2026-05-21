package dag

import (
	"context"
	"fmt"
	dag_builder "risk-guard/src/dag-builder"
	dag_impl "risk-guard/src/dag-impl"
	"risk-guard/src/dag-impl/checks/package/artifact_hash_mismatch"
	"risk-guard/src/dag-impl/checks/package/package_malformed_dependencies"
	"risk-guard/src/dag-impl/checks/package/package_name_mismatch"
	"risk-guard/src/dag-impl/checks/package/package_no_license"
	"risk-guard/src/dag-impl/checks/package/package_registry_mismatch"
	"risk-guard/src/dag-impl/checks/package/package_release_cooldown"
	"risk-guard/src/dag-impl/checks/package/package_source_url_mismatch"
	"risk-guard/src/dag-impl/checks/package/package_stale_release"
	"risk-guard/src/dag-impl/checks/package/package_unreleased_changes"
	"risk-guard/src/dag-impl/checks/package/package_unsafe_source_url"
	"risk-guard/src/dag-impl/checks/source/package_dynamic_name"
	"risk-guard/src/dag-impl/checks/source/package_install_scripts"
	"risk-guard/src/dag-impl/checks/source/package_name_unexported"
	"risk-guard/src/dag-impl/checks/source/source_few_contributors"
	"risk-guard/src/dag-impl/checks/source/source_malformed_metadata"
	"risk-guard/src/dag-impl/checks/source/source_manifest_without_lockfile"
	"risk-guard/src/dag-impl/checks/source/source_no_ci"
	"risk-guard/src/dag-impl/checks/source/source_no_human_commits"
	"risk-guard/src/dag-impl/checks/source/source_no_license"
	"risk-guard/src/dag-impl/checks/source/source_no_security_policy"
	"risk-guard/src/dag-impl/checks/source/source_repo_abandoned"
	"risk-guard/src/dag-impl/checks/source/source_repo_new"
	"risk-guard/src/dag-impl/checks/source/source_repo_not_found"
	"risk-guard/src/dag-impl/checks/source/source_repo_stale"
	"risk-guard/src/dag-impl/checks/source/source_single_contributor"
	"risk-guard/src/dag-impl/checks/source/source_unsupported_manifest_file"
	executiondag "risk-guard/src/execution-dag"
	"risk-guard/src/language"
	localfetcher "risk-guard/src/lib/local/artifact/fetcher"
)

// Builder is the DAG builder used by the local CLI (risk-guard-local <path>).
// Its node list is independent of the server Builder — edit one without
// touching the other. The local profile carries no upstream vulnerability
// data sources.
func Builder(
	dag *executiondag.DAG[dag_impl.Input],
	input *dag_impl.Input,
	langs map[string]language.Language,
	ctx context.Context,
) error {
	if err := dag_builder.BuildGitDag(dag, *input, ctx); err != nil {
		return fmt.Errorf("building git dag: %w", err)
	}
	dag_builder.BuildDag(dag, input, langs, localfetcher.New(), ctx)

	installScriptExtractors := dag_builder.InstallScriptExtractors(langs)

	executiondag.AddNode(dag, source_repo_not_found.NewNode())
	executiondag.AddNode(dag, source_malformed_metadata.NewNode())
	executiondag.AddNode(dag, package_no_license.NewNode())
	executiondag.AddNode(dag, package_registry_mismatch.NewNode())
	executiondag.AddNode(dag, package_unsafe_source_url.NewNode())
	executiondag.AddNode(dag, package_source_url_mismatch.NewNode())
	executiondag.AddNode(dag, package_name_mismatch.NewNode(langs))
	executiondag.AddNode(dag, package_unreleased_changes.NewNode())
	executiondag.AddNode(dag, package_stale_release.NewNode())
	executiondag.AddNode(dag, package_release_cooldown.NewNode())
	executiondag.AddNode(dag, package_malformed_dependencies.NewNode())
	executiondag.AddNode(dag, artifact_hash_mismatch.NewNode())
	executiondag.AddNode(dag, source_no_human_commits.NewNode())
	executiondag.AddNode(dag, source_no_security_policy.NewNode())
	executiondag.AddNode(dag, source_no_ci.NewNode())
	executiondag.AddNode(dag, package_dynamic_name.NewNode())
	executiondag.AddNode(dag, package_install_scripts.NewNode(installScriptExtractors))
	executiondag.AddNode(dag, package_name_unexported.NewNode())
	executiondag.AddNode(dag, source_few_contributors.NewNode())
	executiondag.AddNode(dag, source_repo_new.NewNode())
	executiondag.AddNode(dag, source_single_contributor.NewNode())
	executiondag.AddNode(dag, source_repo_abandoned.NewNode())
	executiondag.AddNode(dag, source_repo_stale.NewNode())
	executiondag.AddNode(dag, source_no_license.NewNode())
	executiondag.AddNode(dag, source_unsupported_manifest_file.NewNode())
	executiondag.AddNode(dag, source_manifest_without_lockfile.NewNode())

	return nil
}
