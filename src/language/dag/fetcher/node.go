package fetcher

import (
	"context"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/registry"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type Node struct {
	Description string                         `json:"description,omitempty"`
	Sources     map[string]executiondag.Source `json:"sources"`
	fetchers    map[string]registry.EcosystemRegistryFetcher
	extraDeps   []any
}

func NewNode(languages map[string]language.Language, extraDeps []any) *Node {
	fetchers := make(map[string]registry.EcosystemRegistryFetcher, len(languages))
	sources := make(map[string]executiondag.Source, len(languages))
	for ecosystem, lang := range languages {
		fetchers[ecosystem] = lang
		sources[ecosystem] = lang.Metadata().Source
	}
	return &Node{
		Description: "Fetches package metadata from language-specific package registries (PyPI, NPM) to gather information about package versions, dependencies, and metadata",
		Sources:     sources,
		fetchers:    fetchers,
		extraDeps:   extraDeps,
	}
}

func (n *Node) GetDependencies() []any {
	return n.extraDeps
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	log := ctxutil.GetLogger(ctx)

	if len(input.Packages) == 0 {
		log.Debug("no packages to fetch")
		return NewOutput(executiondag.StatusSkipped, "no packages to fetch", nil, input), nil
	}

	log.Debug("fetching registry data for packages", zap.Int("count", len(input.Packages)))

	var outputs []RegistryOutput
	var lastError error
	successCount := 0
	skipCount := 0

	for _, pkg := range input.Packages {
		log.Debug("fetching package",
			zap.String("ecosystem", pkg.Ecosystem),
			zap.String("name", pkg.Name))

		fetcher := registry.MustGetFetcher(n.fetchers, pkg.Ecosystem)

		response, err := fetcher.FetchPackageFromRegistry(ctx, pkg)
		if err != nil {
			log.Error("failed to fetch package",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("name", pkg.Name),
				zap.Error(err))
			lastError = err
			continue
		}

		// Create and store the registry output
		outputs = append(outputs, RegistryOutput{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Response:  response,
		})

		if response.StatusCode == 200 {
			successCount++
			log.Debug("successfully fetched package",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("name", pkg.Name),
				zap.Int("status_code", response.StatusCode))
		} else {
			skipCount++
			log.Debug("package fetch returned non-200 status",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("name", pkg.Name),
				zap.Int("status_code", response.StatusCode))
		}
	}

	// Determine overall status
	status := executiondag.StatusSuccess
	statusReason := fmt.Sprintf("fetched %d packages (%d success, %d skipped)", len(outputs), successCount, skipCount)

	if len(outputs) == 0 {
		if lastError != nil {
			return nil, fmt.Errorf("all packages failed to fetch: %w", lastError)
		}
		status = executiondag.StatusSkipped
		statusReason = "all packages skipped (no fetchers available)"
	} else if lastError != nil {
		return nil, fmt.Errorf("partial failure: %d packages succeeded but at least one failed: %w", successCount+skipCount, lastError)
	}

	log.Debug("fetcher node complete",
		zap.String("status", string(status)),
		zap.Int("total", len(input.Packages)),
		zap.Int("success", successCount),
		zap.Int("skipped", skipCount))

	return NewOutput(status, statusReason, outputs, input), nil
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, nil, input)
}

func (n *Node) GetSources() map[string]executiondag.Source { return n.Sources }

func (n *Node) Kind() string {
	return "fetch"
}

// Read loads fetcher data from previous run instead of fetching from registry.
func (n *Node) Read(ctx context.Context, input dag_impl.Input) (*Output, error) {
	return dag_impl.ReadOutput[*Output](ctx, input)
}
