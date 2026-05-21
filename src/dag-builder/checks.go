package dag_builder

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/registry"
	"sort"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

func AggregateChecks(ctx context.Context, dag *executiondag.DAG[dag_impl.Input]) ([]checks.Output, error) {
	log := ctxutil.GetLogger(ctx)

	nodes := dag.GetNodes()
	var checkOutputs []checks.Output

	for _, node := range nodes {
		if node.GetKind() != "check" {
			continue
		}

		if IsDeprecated(node.GetNodeForReflection()) {
			continue
		}

		output := node.GetOutput(ctx)

		if output.GetStatus() == executiondag.StatusSkipped {
			log.Debug("skipping check in aggregation",
				zap.String("reason", output.GetStatusReason()))
			continue
		}

		checkOutput, ok := output.(*checks.Output)
		if !ok {
			return nil, fmt.Errorf("check node output is not *checks.Output: %T", output)
		}

		checkOutputs = append(checkOutputs, *checkOutput)
	}

	sort.Slice(checkOutputs, func(i, j int) bool {
		return checkOutputs[i].Check.CheckCode < checkOutputs[j].Check.CheckCode
	})

	return checkOutputs, nil
}

// InstallScriptExtractors builds the per-ecosystem extractor map used by the
// package_install_scripts check.
func InstallScriptExtractors(languages map[string]language.Language) map[string]registry.ArtifactInstallScriptExtractor {
	extractors := make(map[string]registry.ArtifactInstallScriptExtractor, len(languages))
	for ecosystem, lang := range languages {
		extractors[ecosystem] = lang
	}
	return extractors
}
