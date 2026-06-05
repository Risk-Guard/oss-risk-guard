package main

import (
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	dagcmd "github.com/Risk-Guard/oss-risk-guard/src/cmd/subcommands/dag"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	localdag "github.com/Risk-Guard/oss-risk-guard/src/lib/local/dag"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	outputDir      string
	policyFile     string
	policyOverride string
	policyDefault  string
	evalOutFile    string
	checksOutFile  string
	sarifOutFile   string
)

var auditSourceCmd = &cobra.Command{
	Use:   "source <path>",
	Short: "Score the local source repo only (no dependency audit)",
	Long: `Run the local-source scoring DAG against an on-disk git repository
without auditing its dependencies. With --sarif/--evaluation/--checks the
corresponding artifacts are written; with none of them set, a human-readable
findings summary is printed to the terminal.

Examples:
  risk-guard audit source .
  risk-guard audit source . --sarif out.sarif
  risk-guard audit source /abs/path/to/repo --evaluation eval.yaml --checks checks.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runScoreLocal,
}

func init() {
	registerLocalFlags(auditSourceCmd)
	registerSummaryRenderFlags(auditSourceCmd, false)
	auditCmd.AddCommand(auditSourceCmd)
}

func runScoreLocal(command *cobra.Command, args []string) error {
	path := args[0]

	if checksOutFile != "" {
		command.SetContext(runpath.SetChecksOutputPath(command.Context(), checksOutFile))
	}

	repoPath, err := resolveScanPath(path)
	if err != nil {
		return err
	}

	ctx, overridesHash, err := setupAuditContext(command, repoPath)
	if err != nil {
		return err
	}
	logger := ctxutil.GetLogger(ctx)

	logger.Info("collecting metadata using DAG execution",
		zap.String("path", repoPath),
		zap.String("cacheDir", runpath.GetCacheDir(ctx)))

	input := dag_impl.NewSourceInputWithOverrides(repoPath, nil, false, overridesHash)

	dagResponse, err := dagcmd.BuildAndRunDAG(ctx, input, localdag.Builder)
	if err != nil {
		return fmt.Errorf("failed to collect metadata: %w", err)
	}

	logger.Info("DAG execution complete")

	analysis := extractAnalysisViolations(input, dagResponse.Checks)

	// No output flag set: grade and print a findings summary to the terminal so
	// a bare `audit source <path>` is useful instead of running the DAG silently.
	// (--checks alone still writes only the checks file, handled in-DAG above.)
	if evalOutFile == "" && sarifOutFile == "" && checksOutFile == "" {
		report, err := assembleReport(ctx, input.AnalysisIdentifier, analysis, nil, nil, nil)
		if err != nil {
			return err
		}
		return renderReportSummary(report, summaryModeOverride, summaryGitHub, summaryGitLab, repoPath)
	}

	if evalOutFile != "" || sarifOutFile != "" {
		po := policyOverride
		if po == "" {
			po = policyFile
		}
		result, err := gradeViolations(ctx, input.AnalysisIdentifier, analysis, nil, po, policyDefault)
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

// registerSharedDAGFlags wires the deprecated cache-location flag every
// DAG-running local command still accepts for back-compat.
func registerSharedDAGFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "Deprecated: use --cache-dir instead")
}

func registerLocalFlags(cmd *cobra.Command) {
	registerSharedDAGFlags(cmd)
	cmd.Flags().StringVar(&policyOverride, "policy-override", "", flagHelpPolicyOverride)
	cmd.Flags().StringVar(&policyDefault, "policy-default", "", flagHelpPolicyDefault)
	cmd.Flags().StringVar(&policyFile, "policy", "", "Deprecated: use --policy-override instead")
	cmd.Flags().StringVar(&evalOutFile, "evaluation", "", "Output file for evaluation result (YAML)")
	cmd.Flags().StringVar(&checksOutFile, "checks", "", "Output file for checks result (YAML)")
	cmd.Flags().StringVar(&sarifOutFile, "sarif", "", flagHelpSARIF)
}
