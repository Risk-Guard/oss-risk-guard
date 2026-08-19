package package_stale_release

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/version_transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func makeUnknownDateCtx(t *testing.T, pkg models.PackageInfo, analyzedVersion string, analyzedReleaseDate *time.Time, latest *models.VersionInfo) context.Context {
	t.Helper()
	log, err := logger.NewLogger("error")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	ctx := ctxutil.SetLogger(context.Background(), log)

	transformerOut := transformer.NewOutput(executiondag.StatusSuccess, "test", []transformer.PackageOutput{
		{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Metadata: &models.PackageMetadata{
				Ecosystem:   pkg.Ecosystem,
				PackageName: pkg.Name,
				Version:     &analyzedVersion,
				ReleaseDate: analyzedReleaseDate,
			},
		},
	}, dag_impl.Input{}, nil)

	versionOut := version_transformer.NewOutput(executiondag.StatusSuccess, "test", []version_transformer.VersionOutput{
		{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Metadata:  &models.VersionMetadata{LatestVersion: latest},
		},
	}, dag_impl.Input{})

	ctx = context.WithValue(ctx, executiondag.DependsOn[*transformer.Node](), transformerOut)
	return context.WithValue(ctx, executiondag.DependsOn[*version_transformer.Node](), versionOut)
}

func TestExecute_UndatedLatestVersionDoesNotFallBackToAnalyzedVersion(t *testing.T) {
	pkg := models.PackageInfo{Ecosystem: "maven", Name: "com.example:demo", Version: "1.0.0"}
	longAgo := time.Now().AddDate(-10, 0, 0)

	ctx := makeUnknownDateCtx(t, pkg, "1.0.0", &longAgo,
		&models.VersionInfo{Version: "2.0.0", ReleasedAt: nil})

	output, err := NewNode().Execute(ctx, dag_impl.Input{Packages: []models.PackageInfo{pkg}})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if output.Check.CheckStatus != storage.StatusSkipped {
		t.Errorf("status = %v, want skipped: the analyzed version's date must not stand in for the undated latest release",
			output.Check.CheckStatus)
	}
	if strings.Contains(output.Check.Rationale, "1.0.0") {
		t.Errorf("rationale = %q, want no staleness measured against the analyzed version", output.Check.Rationale)
	}
}

func TestExecute_NoDateAnywhereIsSkippedNotPassed(t *testing.T) {
	pkg := models.PackageInfo{Ecosystem: "maven", Name: "com.example:demo", Version: "1.0.0"}

	ctx := makeUnknownDateCtx(t, pkg, "1.0.0", nil, nil)

	output, err := NewNode().Execute(ctx, dag_impl.Input{Packages: []models.PackageInfo{pkg}})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if output.Check.CheckStatus != storage.StatusSkipped {
		t.Errorf("status = %v, want skipped rather than a compliant 'No packages checked'", output.Check.CheckStatus)
	}
	if !strings.Contains(output.Check.Rationale, "Release dates unavailable") {
		t.Errorf("rationale = %q, want it to state the dates were unavailable", output.Check.Rationale)
	}
}
