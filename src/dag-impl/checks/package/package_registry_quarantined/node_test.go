package package_registry_quarantined

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/fetcher"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func TestCheckCodeConstant(t *testing.T) {
	if NewNode().Code != "PACKAGE_REGISTRY_QUARANTINED" {
		t.Errorf("Expected code PACKAGE_REGISTRY_QUARANTINED, got %s", NewNode().Code)
	}
}

func TestNode_GetDependencies(t *testing.T) {
	deps := NewNode().GetDependencies()
	if len(deps) != 1 {
		t.Fatalf("Expected 1 dependency, got %d", len(deps))
	}
	if deps[0] != executiondag.DependsOn[*fetcher.Node]() {
		t.Error("Node should depend on *fetcher.Node")
	}
}

// makeCtx builds a context carrying a fetcher Output for a single package with the given
// HTTP status and project-status, mirroring what the fetcher node produces at runtime.
func makeCtx(t *testing.T, pkg models.PackageInfo, statusCode int, projectStatus string) context.Context {
	t.Helper()
	log, err := logger.NewLogger("error")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	ctx := ctxutil.SetLogger(context.Background(), log)

	fetcherOut := &fetcher.Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "test", dag_impl.Input{}),
		Outputs: []fetcher.RegistryOutput{
			{
				Ecosystem: pkg.Ecosystem,
				Name:      pkg.Name,
				Response: &language.RegistryResponse{
					StatusCode:    statusCode,
					ProjectStatus: projectStatus,
				},
			},
		},
	}
	return context.WithValue(ctx, executiondag.DependsOn[*fetcher.Node](), fetcherOut)
}

func TestExecute(t *testing.T) {
	tests := []struct {
		name          string
		pkg           models.PackageInfo
		statusCode    int
		projectStatus string
		wantViolation bool
	}{
		{
			name:          "quarantined public package is a violation",
			pkg:           models.PackageInfo{Ecosystem: "pypi", Name: "datacamp-light"},
			statusCode:    404,
			projectStatus: "quarantined",
			wantViolation: true,
		},
		{
			name:          "private quarantined package is not flagged",
			pkg:           models.PackageInfo{Ecosystem: "pypi", Name: "internal", Private: true},
			statusCode:    404,
			projectStatus: "quarantined",
			wantViolation: false,
		},
		{
			name:          "genuinely missing package (no status) is not quarantine",
			pkg:           models.PackageInfo{Ecosystem: "pypi", Name: "never-published"},
			statusCode:    404,
			projectStatus: "",
			wantViolation: false,
		},
		{
			name:          "active package found in registry is compliant",
			pkg:           models.PackageInfo{Ecosystem: "pypi", Name: "requests"},
			statusCode:    200,
			projectStatus: "",
			wantViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := makeCtx(t, tt.pkg, tt.statusCode, tt.projectStatus)
			input := dag_impl.Input{Packages: []models.PackageInfo{tt.pkg}}

			output, err := NewNode().Execute(ctx, input)
			if err != nil {
				t.Fatalf("Execute returned error: %v", err)
			}

			gotViolation := output.Check.CheckStatus == storage.StatusViolation
			if gotViolation != tt.wantViolation {
				t.Errorf("Expected violation=%v, got status %v", tt.wantViolation, output.Check.CheckStatus)
			}
			if output.Check.CheckCode != "PACKAGE_REGISTRY_QUARANTINED" {
				t.Errorf("Expected check code PACKAGE_REGISTRY_QUARANTINED, got %s", output.Check.CheckCode)
			}
		})
	}
}
