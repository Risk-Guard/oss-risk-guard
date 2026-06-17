package package_registry_mismatch

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
			name:          "missing public package is a mismatch",
			pkg:           models.PackageInfo{Ecosystem: "pypi", Name: "never-published"},
			statusCode:    404,
			wantViolation: true,
		},
		{
			name:          "quarantined package is NOT reported as a mismatch",
			pkg:           models.PackageInfo{Ecosystem: "pypi", Name: "datacamp-light"},
			statusCode:    404,
			projectStatus: "quarantined",
			wantViolation: false,
		},
		{
			name:          "found public package is compliant",
			pkg:           models.PackageInfo{Ecosystem: "pypi", Name: "requests"},
			statusCode:    200,
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
		})
	}
}
