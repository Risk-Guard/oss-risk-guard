package checks

import (
	"context"
	"risk-guard/src/dag-impl/deps_extractor"
	"risk-guard/src/dag-impl/policy_loader"
	"risk-guard/src/lib/common/storage"
	"risk-guard/src/models"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
)

func extractDepsForStorage(ctx context.Context, _ dag_impl.Input) ([]models.Dependency, []models.DepsTreeEdge) {
	depsOut := executiondag.GetOutput[*deps_extractor.Node](ctx).(*deps_extractor.Output)

	var freeDeps []models.Dependency
	var lockDeps []models.DepsTreeEdge

	if depsOut.DepsSource == deps_extractor.DepsFromPackage {
		freeDeps = append(freeDeps, depsOut.PackageFreeDeps...)
	} else {
		freeDeps = append(freeDeps, depsOut.SourceFreeDeps...)
		lockDeps = depsOut.SourceLockfileEdges
	}

	return freeDeps, lockDeps
}

func extractPolicyFromContext(ctx context.Context) (*storage.PolicyData, error) {
	policyOut, ok := executiondag.TryGetOutput[*policy_loader.Node](ctx)
	if !ok {
		return nil, nil
	}

	output, ok := policyOut.(*policy_loader.Output)
	if !ok {
		return nil, nil
	}

	if output.Error != "" {
		data := &storage.PolicyData{Error: output.Error}
		return data, nil
	}

	if output.Policy == nil {
		return nil, nil
	}

	data := &storage.PolicyData{
		Policy:  output.Policy,
		RawYAML: output.RawYAML,
	}

	return data, nil
}
