package main

import (
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	dagcmd "github.com/Risk-Guard/oss-risk-guard/src/cmd/subcommands/dag"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var auditPackageCmd = &cobra.Command{
	Use:   "audit-package <package-key>",
	Short: "Score a single package by its analysis-identifier key",
	Long: `Score a single package via the local package DAG and emit SARIF.

The argument is an analysis-identifier key produced by the sbom or audit
commands, e.g. "package/npm/express" or "package/npm/lodash?version=4.17.20".

No cache backend is used; every invocation runs the DAG fresh.

Examples:
  risk-guard-local audit-package 'package/npm/express' --sarif out.sarif
  risk-guard-local audit-package 'package/npm/lodash?version=4.17.20' --sarif out.sarif`,
	Args: cobra.ExactArgs(1),
	RunE: runAuditPackage,
}

func init() {
	registerSharedDAGFlags(auditPackageCmd)
	auditPackageCmd.Flags().StringVar(&policyOverride, "policy-override", "", "Policy file that completely overrides all policy (YAML)")
	auditPackageCmd.Flags().StringVar(&policyDefault, "policy-default", "", "Policy file to use as base instead of global default (YAML)")
	auditPackageCmd.Flags().StringVar(&sarifOutFile, "sarif", "", "Output file for evaluation result (SARIF 2.1.0 JSON)")
	if err := auditPackageCmd.MarkFlagRequired("sarif"); err != nil {
		panic(fmt.Errorf("marking --sarif required: %w", err))
	}
	rootCmd.AddCommand(auditPackageCmd)
}

func runAuditPackage(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	logger := ctxutil.GetLogger(ctx)

	eco, name, version, err := parsePackageKey(args[0])
	if err != nil {
		return err
	}

	// git_clone_content uses the cache backend as its on-disk clone store, so
	// it must be initialized even though audit-package doesn't memoize results.
	ctx, err = cache.InitializeCacheBackend(ctx)
	if err != nil {
		return err
	}
	ctx, err = storage.InitializeStorageBackend(ctx)
	if err != nil {
		return err
	}

	ctx, overridesHash, err := loadAndSetupOverrides(ctx, overridesFile)
	if err != nil {
		return err
	}
	cmd.SetContext(ctx)

	input := dag_impl.NewPackageInputWithVersion(eco, name, version, overridesHash)

	logger.Info("auditing package",
		zap.String("ecosystem", eco),
		zap.String("package", name),
		zap.Stringp("version", version))

	resp, err := dagcmd.BuildAndRunDAG(ctx, input, localdag.PackageBuilder)
	if err != nil {
		return fmt.Errorf("scoring package: %w", err)
	}

	result, err := evaluate(ctx, input, resp.Checks, policyOverride, policyDefault)
	if err != nil {
		return fmt.Errorf("evaluation failed: %w", err)
	}

	if err := writeSARIF(ctx, result, sarifOutFile); err != nil {
		return fmt.Errorf("sarif output failed: %w", err)
	}

	return nil
}

// parsePackageKey decodes an analysis-identifier key of the form
// "package/{eco}/{name}" or "package/{eco}/{name}?version={ver}" into its
// components. Returns nil version when the key has none.
func parsePackageKey(key string) (ecosystem, name string, version *string, err error) {
	eco, n, v := parseKeyIdentity(key)
	if eco == "" || n == "" {
		return "", "", nil, fmt.Errorf("invalid package key %q (expected \"package/<eco>/<name>[?version=...]\")", key)
	}
	if v == "" {
		return eco, n, nil, nil
	}
	return eco, n, &v, nil
}
