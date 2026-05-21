package artifact_fetch

import (
	"context"
	"fmt"
	"risk-guard/src/api/routes"
	"risk-guard/src/artifact/fetcher"
	"risk-guard/src/ctxutil"
	"risk-guard/src/language"
	"risk-guard/src/language/dag/transformer"

	"go.uber.org/zap"

	dag_impl "risk-guard/src/dag-impl"

	executiondag "risk-guard/src/execution-dag"
)

type Node struct {
	Description string `json:"description,omitempty"`
	fetcher     fetcher.Fetcher
}

func NewNode(languages map[string]language.Language, f fetcher.Fetcher) *Node {
	return &Node{
		Description: "Downloads and extracts distributed package artifacts for verification",
		fetcher:     f,
	}
}

func (n *Node) GetDependencies() []any {
	return []any{executiondag.DependsOn[*transformer.Node]()}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	log := ctxutil.GetLogger(ctx)

	if n.fetcher == nil {
		return NewOutput(executiondag.StatusSkipped, "no artifact fetcher configured", nil, input), nil
	}

	if len(input.Packages) == 0 {
		return NewOutput(executiondag.StatusSkipped, "no packages", nil, input), nil
	}

	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)

	var extractions []routes.ArtifactExtraction
	successCount := 0

	for _, pkg := range input.Packages {
		pkgMeta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name)
		if pkgMeta == nil {
			skipReason := "no package metadata"
			extractions = append(extractions, routes.ArtifactExtraction{
				Ecosystem:   pkg.Ecosystem,
				PackageName: pkg.Name,
				SkipReason:  &skipReason,
			})
			continue
		}

		if pkgMeta.Distribution == nil || pkgMeta.Distribution.URL == "" {
			skipReason := "no distribution URL"
			extractions = append(extractions, routes.ArtifactExtraction{
				Ecosystem:   pkg.Ecosystem,
				PackageName: pkg.Name,
				SkipReason:  &skipReason,
			})
			continue
		}

		extraction, err := n.fetcher.Fetch(ctx, pkg, pkgMeta.Distribution)
		if err != nil {
			return nil, fmt.Errorf("fetching %s/%s: %w", pkg.Ecosystem, pkg.Name, err)
		}

		extractions = append(extractions, *extraction)
		if extraction.SkipReason == nil {
			successCount++
		}
	}

	status := executiondag.StatusSuccess
	statusReason := fmt.Sprintf("extracted %d/%d artifacts", successCount, len(input.Packages))

	if successCount == 0 {
		status = executiondag.StatusSkipped
		statusReason = "no artifacts extracted"
	}

	log.Debug("artifact fetch complete",
		zap.String("status", string(status)),
		zap.Int("extracted", successCount),
		zap.Int("total", len(input.Packages)))

	return NewOutput(status, statusReason, extractions, input), nil
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, nil, input)
}

func (n *Node) Kind() string {
	return "fetch"
}

func (n *Node) Read(ctx context.Context, input dag_impl.Input) (*Output, error) {
	output, err := dag_impl.ReadOutput[*Output](ctx, input)
	if err != nil {
		return nil, fmt.Errorf("reading cached artifact: %w", err)
	}
	return output, nil
}
