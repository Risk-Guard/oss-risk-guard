package dag

import (
	"context"
	"fmt"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/artifact_hash_mismatch"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_malformed_dependencies"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_name_mismatch"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_no_license"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_registry_mismatch"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_release_cooldown"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_source_url_mismatch"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_stale_release"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_unreleased_changes"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/package/package_unsafe_source_url"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/package_dynamic_name"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/package_install_scripts"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/package_name_unexported"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_few_contributors"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_malformed_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_manifest_without_lockfile"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_no_ci"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_no_human_commits"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_no_license"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_no_security_policy"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_repo_abandoned"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_repo_new"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_repo_not_found"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_repo_stale"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_single_contributor"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks/source/source_unsupported_manifest_file"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	localfetcher "github.com/Risk-Guard/oss-risk-guard/src/lib/local/artifact/fetcher"
)

// PackageBuilder is the DAG builder for scoring a package-shape input on the
// local CLI (audit / audit-package). BuildGitDag resolves the source URL from
// registry metadata and clones it, then the same check set as Builder runs.
// No upstream vulnerability data sources, matching the local profile.
func PackageBuilder(
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
