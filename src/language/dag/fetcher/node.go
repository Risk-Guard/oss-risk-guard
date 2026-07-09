package fetcher

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/progress"
	"github.com/Risk-Guard/oss-risk-guard/src/registry"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// fetchConcurrency bounds how many packages are fetched from registries at once
// during the bulk prefetch. Modest so npm/PyPI don't rate-limit the burst.
const fetchConcurrency = 10

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

	packages := dedupePackages(input.Packages)
	total := len(packages)
	log.Debug("fetching registry data for packages", zap.Int("count", total))

	// Show live per-package rows only for the bulk prefetch. A per-package
	// audit DAG fetches exactly one package and already shows its own audit
	// row, so there we stay sequential and quiet.
	showProgress := total > 1
	disp := progress.FromContext(ctx)
	if showProgress {
		disp.Print(fmt.Sprintf("Fetching metadata for %d packages…\n", total))
	}

	limit := fetchConcurrency
	if !showProgress {
		limit = 1
	}

	var (
		mu           sync.Mutex
		outputs      []RegistryOutput
		lastError    error
		successCount int
		skipCount    int
		done         int
		pos          atomic.Int64
	)

	g := new(errgroup.Group)
	g.SetLimit(limit)
	for _, pkg := range packages {
		g.Go(func() error {
			// Each row is one package: "[idx/total] eco/name  M:SS  (node)".
			var task *progress.Task
			if showProgress {
				idx := pos.Add(1)
				task = disp.Start(fmt.Sprintf("[%d/%d] %s/%s", idx, total, pkg.Ecosystem, pkg.Name), "fetching registry metadata")
			}
			log.Debug("fetching package",
				zap.String("ecosystem", pkg.Ecosystem),
				zap.String("name", pkg.Name))

			response, err := registry.MustGetFetcher(n.fetchers, pkg.Ecosystem).FetchPackageFromRegistry(ctx, pkg)
			if task != nil {
				task.Done()
			}

			mu.Lock()
			done++
			n := done
			if err != nil {
				lastError = err
				mu.Unlock()
				log.Error("failed to fetch package",
					zap.String("ecosystem", pkg.Ecosystem),
					zap.String("name", pkg.Name),
					zap.Error(err))
				// Lock the failure in above the live rows so it stays visible.
				if showProgress {
					disp.Print(fmt.Sprintf("✗ %s/%s  (%d/%d)\n", pkg.Ecosystem, pkg.Name, n, total))
				}
				return nil
			}
			outputs = append(outputs, RegistryOutput{
				Ecosystem: pkg.Ecosystem,
				Name:      pkg.Name,
				Response:  response,
			})
			if response.StatusCode == 200 {
				successCount++
			} else {
				skipCount++
			}
			mu.Unlock()
			if showProgress {
				disp.Print(fmt.Sprintf("✓ %s/%s  (%d/%d)\n", pkg.Ecosystem, pkg.Name, n, total))
			}
			return nil
		})
	}
	_ = g.Wait() // goroutines never return an error; failures are recorded in lastError

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
		zap.Int("total", total),
		zap.Int("success", successCount),
		zap.Int("skipped", skipCount))

	return NewOutput(status, statusReason, outputs, input), nil
}

// dedupePackages removes duplicate packages (same ecosystem+name) so two
// goroutines never write the same cache key concurrently — os.WriteFile is not
// atomic, so a duplicate could otherwise cause a torn read. Order is preserved.
func dedupePackages(packages []models.PackageInfo) []models.PackageInfo {
	seen := make(map[string]struct{}, len(packages))
	out := make([]models.PackageInfo, 0, len(packages))
	for _, pkg := range packages {
		key := pkg.Ecosystem + "/" + pkg.Name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, pkg)
	}
	return out
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
