package main

import (
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	dagcmd "github.com/Risk-Guard/oss-risk-guard/src/cmd/subcommands/dag"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	outputDir      string
	overridesFile  string
	policyFile     string
	policyOverride string
	policyDefault  string
	evalOutFile    string
	checksOutFile  string
	sarifOutFile   string
)

func runScoreLocal(command *cobra.Command, args []string) error {
	logger := ctxutil.GetLogger(command.Context())
	path := args[0]

	ctx := command.Context()

	if checksOutFile != "" {
		ctx = runpath.SetChecksOutputPath(ctx, checksOutFile)
	}

	repoPath, err := git.ValidateGitRepo(path)
	if err != nil {
		return fmt.Errorf("invalid git repository: %w", err)
	}

	ctx, err = cache.InitializeCacheBackend(ctx)
	if err != nil {
		return err
	}
	ctx, err = storage.InitializeStorageBackend(ctx)
	if err != nil {
		return err
	}

	var overridesHash string
	ctx, overridesHash, err = loadAndSetupOverrides(ctx, overridesFile)
	if err != nil {
		return err
	}

	command.SetContext(ctx)

	logger.Info("collecting metadata using DAG execution",
		zap.String("path", repoPath),
		zap.String("cacheDir", runpath.GetCacheDir(ctx)))

	input := dag_impl.NewSourceInputWithOverrides(repoPath, nil, false, overridesHash)

	dagResponse, err := dagcmd.BuildAndRunDAG(ctx, input, localdag.Builder)
	if err != nil {
		return fmt.Errorf("failed to collect metadata: %w", err)
	}

	logger.Info("DAG execution complete")

	if evalOutFile != "" || sarifOutFile != "" {
		po := policyOverride
		if po == "" {
			po = policyFile
		}
		result, err := evaluate(ctx, input, dagResponse.Checks, po, policyDefault)
		if err != nil {
			return fmt.Errorf("evaluation failed: %w", err)
		}
		if evalOutFile != "" {
			if err := writeEvaluationYAML(ctx, result, evalOutFile); err != nil {
				return fmt.Errorf("evaluation failed: %w", err)
			}
		}
		if sarifOutFile != "" {
			if err := writeSARIF(ctx, result, sarifOutFile); err != nil {
				return fmt.Errorf("sarif output failed: %w", err)
			}
		}
	}

	return nil
}

// registerSharedDAGFlags wires the flags every DAG-running local command needs:
// where to write artifacts, which overrides to apply, and which commit to scan.
func registerSharedDAGFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "Deprecated: use --cache-dir instead")
	cmd.Flags().StringVar(&overridesFile, "overrides", "", "YAML file with field overrides")
}

func registerLocalFlags(cmd *cobra.Command) {
	registerSharedDAGFlags(cmd)
	cmd.Flags().StringVar(&policyOverride, "policy-override", "", "Policy file that completely overrides all policy (YAML)")
	cmd.Flags().StringVar(&policyDefault, "policy-default", "", "Policy file to use as base instead of global default (YAML)")
	cmd.Flags().StringVar(&policyFile, "policy", "", "Deprecated: use --policy-override instead")
	cmd.Flags().StringVar(&evalOutFile, "evaluation", "", "Output file for evaluation result (YAML)")
	cmd.Flags().StringVar(&checksOutFile, "checks", "", "Output file for checks result (YAML)")
	cmd.Flags().StringVar(&sarifOutFile, "sarif", "", "Output file for evaluation result (SARIF 2.1.0 JSON)")
}
