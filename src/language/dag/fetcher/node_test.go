package fetcher_test

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/fetcher"
	"github.com/Risk-Guard/oss-risk-guard/src/language/metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

// mockLanguage is a mock implementation of the Language interface for testing.
type mockLanguage struct {
	ecosystem string
	response  *language.RegistryResponse
	err       error
}

func (m *mockLanguage) NormalizeName(name string) string { return name }

func (m *mockLanguage) FetchPackageFromRegistry(_ context.Context, _ models.PackageInfo) (*language.RegistryResponse, error) {
	return m.response, m.err
}

func (m *mockLanguage) ExtractPackageMetadata(_ context.Context, _ models.PackageInfo, _ any) (*models.PackageMetadata, *string, *string, error) {
	return nil, nil, nil, nil
}

func (m *mockLanguage) ExtractVersionHistory(_ context.Context, _ models.PackageInfo, _ any) (*models.VersionMetadata, error) {
	return nil, nil
}

func (m *mockLanguage) Metadata() *metadata.Metadata {
	return &metadata.Metadata{
		Ecosystem:   m.ecosystem,
		DisplayName: m.ecosystem,
		Source: executiondag.Source{
			Name:        m.ecosystem + " Registry",
			URL:         "https://example.com",
			Description: "Mock registry for " + m.ecosystem,
			Category:    executiondag.SourceCategoryRegistry,
		},
		OSVEcosystem:         m.ecosystem,
		GHSAEcosystem:        m.ecosystem,
		PackageURLFormat:     "%s/%s",
		PackagePageURLFormat: "https://example.com/package/%s",
	}
}

func (m *mockLanguage) DependencyFilePatterns() []string {
	return []string{}
}

func (m *mockLanguage) SkipDirectories() []string {
	return []string{}
}

func (m *mockLanguage) CompareVersions(_, _ string) (int, error) {
	return 0, nil
}

func (m *mockLanguage) ExtractPackageArchive(_, _ string) error {
	return nil
}

func (m *mockLanguage) ExtractInstallScriptsFromFiles(_ map[string]string) ([]string, error) {
	return nil, nil
}

func TestNode_Execute_NoPackages(t *testing.T) {
	// Setup
	ctx := context.Background()
	ctx = ctxutil.SetLogger(ctx, zap.NewNop())
	cfg := &environment.Config{}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = runpath.SetOutputDir(ctx, t.TempDir())

	node := fetcher.NewNode(map[string]language.Language{}, nil)
	input := &dag_impl.Input{Packages: []models.PackageInfo{}}

	// Execute
	output, err := node.Execute(ctx, *input)
	// Assert
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if output.GetStatus() != executiondag.StatusSkipped {
		t.Errorf("expected status skipped, got %v", output.GetStatus())
	}
}

func TestNode_Execute_SinglePackage_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	ctx = ctxutil.SetLogger(ctx, zap.NewNop())
	cfg := &environment.Config{}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = runpath.SetOutputDir(ctx, t.TempDir())

	mockResp := &language.RegistryResponse{
		Data:       map[string]any{"name": "test"},
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
	}

	languages := map[string]language.Language{
		"npm": &mockLanguage{
			ecosystem: "npm",
			response:  mockResp,
		},
	}

	node := fetcher.NewNode(languages, nil)
	input := &dag_impl.Input{
		Packages: []models.PackageInfo{
			{Ecosystem: "npm", Name: "express"},
		},
	}

	// Execute
	output, err := node.Execute(ctx, *input)
	// Assert
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if output.GetStatus() != executiondag.StatusSuccess {
		t.Errorf("expected status success, got %v", output.GetStatus())
	}

	// Check registry data
	resp := output.GetRegistryResponse("npm", "express")
	if resp == nil {
		t.Fatal("expected registry response for npm/express")
		return
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected status code 200, got %d", resp.StatusCode)
	}
}

func TestNode_Execute_MultiplePackages_MixedEcosystems(t *testing.T) {
	// Setup
	ctx := context.Background()
	ctx = ctxutil.SetLogger(ctx, zap.NewNop())
	cfg := &environment.Config{}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = runpath.SetOutputDir(ctx, t.TempDir())

	npmResp := &language.RegistryResponse{
		Data:       map[string]any{"name": "express"},
		StatusCode: 200,
	}

	pypiResp := &language.RegistryResponse{
		Data:       map[string]any{"name": "requests"},
		StatusCode: 200,
	}

	languages := map[string]language.Language{
		"npm": &mockLanguage{
			ecosystem: "npm",
			response:  npmResp,
		},
		"pypi": &mockLanguage{
			ecosystem: "pypi",
			response:  pypiResp,
		},
	}

	node := fetcher.NewNode(languages, nil)
	input := &dag_impl.Input{
		Packages: []models.PackageInfo{
			{Ecosystem: "npm", Name: "express"},
			{Ecosystem: "pypi", Name: "requests"},
		},
	}

	// Execute
	output, err := node.Execute(ctx, *input)
	// Assert
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if output.GetStatus() != executiondag.StatusSuccess {
		t.Errorf("expected status success, got %v", output.GetStatus())
	}

	// Check both packages were fetched
	if len(output.Outputs) != 2 {
		t.Errorf("expected 2 registry responses, got %d", len(output.Outputs))
	}

	npmOutput := output.GetRegistryResponse("npm", "express")
	if npmOutput == nil {
		t.Error("expected registry response for npm/express")
	}

	pypiOutput := output.GetRegistryResponse("pypi", "requests")
	if pypiOutput == nil {
		t.Error("expected registry response for pypi/requests")
	}
}

func TestNode_GetDependencies(t *testing.T) {
	node := fetcher.NewNode(nil, nil)
	deps := node.GetDependencies()

	if len(deps) != 0 {
		t.Errorf("expected no dependencies, got %v", deps)
	}
}

func TestNode_CreateSkippedOutput(t *testing.T) {
	node := fetcher.NewNode(nil, nil)
	output := node.CreateSkippedOutput("test reason", dag_impl.Input{})

	if output.GetStatus() != executiondag.StatusSkipped {
		t.Errorf("expected status skipped, got %v", output.GetStatus())
	}
	if output.GetStatusReason() != "test reason" {
		t.Errorf("expected reason 'test reason', got %q", output.GetStatusReason())
	}
}
