package dag_builder

import (
	"context"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
)

type DagBuilder func(
	dag *executiondag.DAG[dag_impl.Input],
	input *dag_impl.Input,
	langs map[string]language.Language,
	ctx context.Context,
) error
