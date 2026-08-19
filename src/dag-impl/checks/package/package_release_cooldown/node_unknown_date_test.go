package package_release_cooldown

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/checks"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/version_transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func makeUnknownDateCtx(t *testing.T, outputs []version_transformer.VersionOutput) context.Context {
	t.Helper()
	log, err := logger.NewLogger("error")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	ctx := ctxutil.SetLogger(context.Background(), log)

	versionOut := version_transformer.NewOutput(executiondag.StatusSuccess, "test", outputs, dag_impl.Input{})
	return context.WithValue(ctx, executiondag.DependsOn[*version_transformer.Node](), versionOut)
}

func versionOutput(ecosystem, name, version string, releasedAt *time.Time) version_transformer.VersionOutput {
	return version_transformer.VersionOutput{
		Ecosystem: ecosystem,
		Name:      name,
		Metadata: &models.VersionMetadata{
			Versions: []models.VersionInfo{{Version: version, ReleasedAt: releasedAt}},
			LatestVersion: &models.VersionInfo{
				Version:    version,
				ReleasedAt: releasedAt,
			},
		},
	}
}

func TestExecute_UndatedPackageIsSkippedNotPassed(t *testing.T) {
	pkg := models.PackageInfo{Ecosystem: "maven", Name: "com.example:demo", Version: "1.0.0"}
	ctx := makeUnknownDateCtx(t, []version_transformer.VersionOutput{
		versionOutput(pkg.Ecosystem, pkg.Name, pkg.Version, nil),
	})

	output, err := NewNode().Execute(ctx, dag_impl.Input{Packages: []models.PackageInfo{pkg}})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if output.Check.CheckStatus != storage.StatusSkipped {
		t.Errorf("status = %v, want skipped (an unmeasured cooldown must not read as a pass)", output.Check.CheckStatus)
	}
	if !strings.Contains(output.Check.Rationale, "Release dates unavailable") {
		t.Errorf("rationale = %q, want it to state the dates were unavailable", output.Check.Rationale)
	}
}

func TestExecute_UnknownDatesSurviveViolationEvidenceTruncation(t *testing.T) {
	justReleased := time.Now().AddDate(0, 0, -1)

	var packages []models.PackageInfo
	var outputs []version_transformer.VersionOutput
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		pkg := models.PackageInfo{Ecosystem: "npm", Name: name, Version: "1.0.0"}
		packages = append(packages, pkg)
		outputs = append(outputs, versionOutput(pkg.Ecosystem, pkg.Name, pkg.Version, &justReleased))
	}
	undated := models.PackageInfo{Ecosystem: "maven", Name: "com.example:demo", Version: "1.0.0"}
	packages = append(packages, undated)
	outputs = append(outputs, versionOutput(undated.Ecosystem, undated.Name, undated.Version, nil))

	ctx := makeUnknownDateCtx(t, outputs)

	output, err := NewNode().Execute(ctx, dag_impl.Input{Packages: packages})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if output.Check.CheckStatus != storage.StatusViolation {
		t.Fatalf("status = %v, want violation", output.Check.CheckStatus)
	}
	if len(output.Check.Evidence) > checks.MaxEvidenceItems {
		t.Errorf("evidence has %d items, want at most %d", len(output.Check.Evidence), checks.MaxEvidenceItems)
	}
	if !strings.Contains(output.Check.Rationale, "not evaluated") {
		t.Errorf("rationale = %q, want the unknown-date packages reported even though evidence was truncated", output.Check.Rationale)
	}
}
