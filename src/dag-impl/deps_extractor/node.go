package deps_extractor

import (
	"context"
	"fmt"
	"risk-guard/src/ctxutil"
	"risk-guard/src/dag-impl/package_detector"
	"risk-guard/src/language/dag/transformer"

	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type Node struct{}

func NewNode() *Node {
	return &Node{}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	out := NewOutput(executiondag.StatusSuccess, "", input)

	if input.HasSourceKey() {
		out.DepsSource = DepsFromSource
	} else {
		out.DepsSource = DepsFromPackage
	}
	n.extractSourceDeps(ctx, out)
	n.extractPackageDepsFromTransformer(ctx, input, out, logger)

	total := len(out.SourceFreeDeps) + len(out.SourceLockfileEdges) + len(out.PackageFreeDeps)
	out.StatusReason = fmt.Sprintf("extracted %d dependency entries", total)
	logger.Info("deps_extractor complete",
		zap.Int("source_free_deps", len(out.SourceFreeDeps)),
		zap.Int("source_lockfile_edges", len(out.SourceLockfileEdges)),
		zap.Int("package_free_deps", len(out.PackageFreeDeps)),
	)

	return out, nil
}

func (n *Node) extractSourceDeps(ctx context.Context, out *Output) {
	pkgDetectorOut, ok := executiondag.TryGetOutput[*package_detector.Node](ctx)
	if !ok {
		return
	}
	pdOutput := pkgDetectorOut.(*package_detector.Output)

	for _, m := range pdOutput.DetectedManifests {
		if len(m.LockfileDependencies) > 0 {
			out.SourceLockfileEdges = append(out.SourceLockfileEdges, m.LockfileDependencies...)
		} else {
			out.SourceFreeDeps = append(out.SourceFreeDeps, m.Dependencies...)
		}
	}
}

func (n *Node) extractPackageDepsFromTransformer(ctx context.Context, input dag_impl.Input, out *Output, logger *zap.Logger) {
	transformerOut, ok := executiondag.TryGetOutput[*transformer.Node](ctx)
	if !ok {
		return
	}
	tOutput := transformerOut.(*transformer.Output)

	for _, pkg := range input.Packages {
		pkgMeta := tOutput.GetPackageMetadata(pkg.Ecosystem, pkg.Name)
		if pkgMeta == nil {
			logger.Warn("deps_extractor: package metadata not found in transformer output",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("name", pkg.Name),
			)
			continue
		}
		out.PackageFreeDeps = append(out.PackageFreeDeps, pkgMeta.Dependencies...)
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*package_detector.Node](),
		executiondag.DependsOn[*transformer.Node](),
	}
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, input)
}

func (n *Node) Kind() string {
	return "transform"
}

func (n *Node) AllowAutoSkip() bool {
	return false
}
