package version_transformer

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/fetcher"
	"github.com/Risk-Guard/oss-risk-guard/src/registry"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type Node struct {
	Description string `json:"description,omitempty"`
	extractors  map[string]registry.VersionHistoryExtractor
}

func NewNode(languages map[string]language.Language) *Node {
	extractors := make(map[string]registry.VersionHistoryExtractor, len(languages))
	for ecosystem, lang := range languages {
		extractors[ecosystem] = lang
	}
	return &Node{
		Description: "Transforms package registry data into version history metadata for timeline analysis",
		extractors:  extractors,
	}
}

func (n *Node) GetDependencies() []any {
	return []any{executiondag.DependsOn[*fetcher.Node]()}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	log := ctxutil.GetLogger(ctx)

	// Get fetcher output from context (guaranteed to exist by DAG)
	fetcherOut := executiondag.GetOutput[*fetcher.Node](ctx).(*fetcher.Output)

	if len(input.Packages) == 0 {
		log.Debug("no packages to transform version data")
		return NewOutput(executiondag.StatusSkipped, "no packages to transform", nil, input), nil
	}

	log.Debug("transforming version data for packages", zap.Int("count", len(input.Packages)))

	var outputs []VersionOutput
	var lastError error
	successCount := 0
	skipCount := 0

	for _, pkg := range input.Packages {
		log.Debug("transforming version data for package",
			zap.String("ecosystem", pkg.Ecosystem),
			zap.String("name", pkg.Name))

		extractor := registry.MustGetVersionHistoryExtractor(n.extractors, pkg.Ecosystem)

		registryResp := fetcherOut.GetRegistryResponse(pkg.Ecosystem, pkg.Name)
		if registryResp == nil {
			return nil, fmt.Errorf("no registry data found for package %s/%s", pkg.Ecosystem, pkg.Name)
		}

		if registryResp.StatusCode != 200 {
			log.Debug("package fetch was not successful, skipping version transformation",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("package", pkg.Name),
				zap.Int("status_code", registryResp.StatusCode))
			skipCount++
			continue
		}

		releaseData := registryResp.ReleaseData
		if releaseData == nil {
			releaseData = registryResp.Data
		}
		versionMeta, err := extractor.ExtractVersionHistory(ctx, pkg, releaseData)
		if err != nil {
			log.Error("failed to transform version data",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("name", pkg.Name),
				zap.Error(err))
			lastError = err
			continue
		}

		// Create and store the version output
		outputs = append(outputs, VersionOutput{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Metadata:  versionMeta,
		})
		successCount++

		log.Debug("successfully transformed version data",
			zap.String("ecosystem", pkg.Ecosystem),
			zap.String("name", pkg.Name),
			zap.Int("version_count", len(versionMeta.Versions)))
	}

	// Determine overall status
	status := executiondag.StatusSuccess
	statusReason := fmt.Sprintf("transformed version data for %d packages (%d success, %d skipped)", len(outputs), successCount, skipCount)

	if len(outputs) == 0 {
		if lastError != nil {
			return nil, fmt.Errorf("all packages failed to transform version data: %w", lastError)
		}
		status = executiondag.StatusSkipped
		statusReason = "all packages skipped (no transformers available or no successful fetches)"
	} else if skipCount > 0 && successCount == 0 {
		status = executiondag.StatusSkipped
		statusReason = fmt.Sprintf("all %d packages skipped", skipCount)
	} else if lastError != nil {
		// Some packages succeeded but at least one failed
		return nil, fmt.Errorf("partial failure: %d packages succeeded but at least one failed: %w", successCount, lastError)
	}

	log.Debug("version transformer node complete",
		zap.String("status", string(status)),
		zap.Int("total", len(input.Packages)),
		zap.Int("success", successCount),
		zap.Int("skipped", skipCount))

	return NewOutput(status, statusReason, outputs, input), nil
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, nil, input)
}

func (n *Node) Kind() string {
	return "transform"
}
