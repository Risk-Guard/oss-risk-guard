package dag_builder

import (
	"context"
	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
	"risk-guard/src/language"
)

type DagBuilder func(
	dag *executiondag.DAG[dag_impl.Input],
	input *dag_impl.Input,
	langs map[string]language.Language,
	ctx context.Context,
) error
